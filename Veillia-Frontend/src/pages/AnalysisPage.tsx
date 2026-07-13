import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Search, AlertTriangle, CheckCircle2, Info, Loader2, Eye, ZoomIn, X, Lock, ShieldAlert, MousePointerClick } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { analysisService, remediationService } from '../services/api';
import confetti from 'canvas-confetti';

interface AnalysisResult {
  is_phishing: boolean;
  probability: number;
  confidence: number;
  ml_score: number;
  llm_score: number;
  final_score: number;
  decision_source: string;
  engine_disagreement: boolean;
  explanation: string[];
  attack_type: string;
  techniques: string[];
  recommended_training: string[];
  quiz?: TrainingQuiz;
}

interface TrainingQuiz {
  attack_type: string;
  question: string;
  options: string[];
  xp_reward: number;
  vigilance_reward: number;
}

function toClassification(result: AnalysisResult): 'Safe' | 'Suspicious' | 'Dangerous' {
  if (result.confidence >= 70) return result.is_phishing ? 'Dangerous' : 'Safe';
  if (result.is_phishing) return 'Suspicious';
  return 'Safe';
}

const TRAINING_CONTENTS: Record<string, { title: string; description: string; reflexes: string[]; iconType: 'urgency' | 'authority' | 'credential' | 'brand' | 'link' | 'high_risk' | 'extortion' | 'general' }> = {
  "Identifier la pression temporelle": {
    title: "Identifier la pression temporelle",
    description: "L'urgence artificielle est la technique N°1 du phishing. L'attaquant cherche à court-circuiter votre réflexion.",
    reflexes: [
      "Ne cédez pas à la panique (ex: 'votre compte va être fermé sous 24h').",
      "Prenez toujours 5 minutes pour analyser froidement la demande.",
      "Vérifiez l'expéditeur réel ou contactez-le par un autre canal (ex: téléphone)."
    ],
    iconType: 'urgency'
  },
  "Vérifier les demandes venant de la direction": {
    title: "Vérifier les demandes venant de la direction",
    description: "Comprendre et déjouer la Fraude au Président (CEO Fraud) et l'usurpation de la hiérarchie.",
    reflexes: [
      "Ne contournez jamais les procédures habituelles de virement ou de partage de données.",
      "Contactez directement le dirigeant par un canal de confiance (téléphone, Teams) pour validation.",
      "Signalez toute demande inhabituelle ou confidentielle suspecte à l'IT."
    ],
    iconType: 'authority'
  },
  "Protéger ses identifiants": {
    title: "Protéger ses identifiants",
    description: "Éviter le vol de mots de passe (Credential Phishing) via de fausses pages de connexion.",
    reflexes: [
      "Ne saisissez jamais votre mot de passe après avoir cliqué sur un lien reçu par email.",
      "Utilisez un gestionnaire de mots de passe qui détectera les fausses URL.",
      "Activez la double authentification (MFA / 2-Factor) sur tous vos comptes sensibles."
    ],
    iconType: 'credential'
  },
  "Reconnaître l'usurpation de marque": {
    title: "Reconnaître l'usurpation de marque",
    description: "Repérer les usurpations d'identité d'entreprises connues (Amazon, Netflix, La Poste).",
    reflexes: [
      "Inspectez attentivement l'adresse email réelle de l'expéditeur, pas uniquement son nom.",
      "Allez directement sur le site officiel de l'entreprise via votre navigateur sans cliquer sur le lien.",
      "Méfiez-vous des promesses de gains, de remboursements ou de blocages de colis."
    ],
    iconType: 'brand'
  },
  "Inspecter les liens avant de cliquer": {
    title: "Inspecter les liens avant de cliquer",
    description: "Vérifier les adresses URL et repérer les redirections cachées et trompeuses.",
    reflexes: [
      "Passez le curseur (sans cliquer) sur le lien pour afficher l'adresse de destination réelle.",
      "Faites attention aux domaines très similaires (ex: paypa1.com ou secure-banque.com).",
      "Évitez de cliquer sur des liens raccourcis (bit.ly, tinyurl) dont la destination est masquée."
    ],
    iconType: 'link'
  },
  "Reconnaître les liens à risque élevé": {
    title: "Reconnaître les liens à risque élevé",
    description: "Identifier les extensions de domaine suspectes et les faux hébergements.",
    reflexes: [
      "Méfiez-vous des extensions exotiques moins sécurisées (.xyz, .top, .click, .zip).",
      "Attention aux liens qui hébergent des formulaires directement sur des fichiers HTML isolés.",
      "Vérifiez l'absence de caractères spéciaux inhabituels ou d'alphabets russes/cyrilliques."
    ],
    iconType: 'high_risk'
  },
  "Réagir aux menaces et tentatives de chantage": {
    title: "Réagir aux menaces et tentatives de chantage",
    description: "Faire face aux arnaques à l'extorsion, au chantage à la webcam ou aux rançons.",
    reflexes: [
      "Ne payez jamais la rançon demandée : cela encourage les criminels et ne garantit rien.",
      "Changez vos mots de passe s'ils sont mentionnés dans l'email (souvent issus de vieilles fuites).",
      "Masquez physiquement votre webcam et signalez le message à Cybermalveillance.gouv.fr."
    ],
    iconType: 'extortion'
  },
  "Bonnes pratiques de vigilance email": {
    title: "Bonnes pratiques de vigilance email",
    description: "Les règles d'or de cybersécurité pour naviguer en toute sécurité au quotidien.",
    reflexes: [
      "Si une offre semble trop belle pour être vraie, c'est probablement une arnaque.",
      "Ne téléchargez jamais de pièces jointes suspectes (ex: .exe, .scr, ou fichiers Excel macro).",
      "Au moindre doute, copiez-collez l'email dans Veillia ou contactez un administrateur."
    ],
    iconType: 'general'
  }
};

export const AnalysisPage: React.FC = () => {
  const { token, updateUser } = useAuth();
  const [content, setContent] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');
  const [isReporting, setIsReporting] = useState(false);
  const [reportSuccess, setReportSuccess] = useState(false);
  const [selectedTraining, setSelectedTraining] = useState<string | null>(null);

  const [isBlocked, setIsBlocked] = useState(false);
  const [quizAnswer, setQuizAnswer] = useState('');
  const [quizError, setQuizError] = useState('');
  const [quizSuccess, setQuizSuccess] = useState(false);
  const [analysisQuizAnswer, setAnalysisQuizAnswer] = useState('');
  const [analysisQuizFeedback, setAnalysisQuizFeedback] = useState<any>(null);
  const [isSubmittingAnalysisQuiz, setIsSubmittingAnalysisQuiz] = useState(false);

  const [sandboxImage, setSandboxImage] = useState<string | null>(null);
  const [isSandboxLoading, setIsSandboxLoading] = useState(false);

  // UX Features States
  const [isLightboxOpen, setIsLightboxOpen] = useState(false);
  const [showComparison, setShowComparison] = useState(false);
  const [detectedBrand, setDetectedBrand] = useState<string | null>(null);

  const [uploadResult, setUploadResult] = useState<any>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [analysisStep, setAnalysisStep] = useState("");

  const SCAN_STEPS = [
    "Extraction du contenu...",
    "Analyse sémantique par NLP...",
    "Vérification de la structure des liens...",
    "Évaluation des signaux de phishing..."
  ];

  useEffect(() => {
    async function checkStatus() {
      try {
        const { is_blocked } = await remediationService.getStatus();
        setIsBlocked(is_blocked);
      } catch (err) {
        console.error("Erreur statut remédiation:", err);
      }
    }
    checkStatus();
  }, []);

  const handleQuizSubmit = async () => {
    if (quizAnswer === 'urgence') {
      try {
        await remediationService.complete();
        setQuizSuccess(true);
        setTimeout(() => {
          setIsBlocked(false);
          setQuizSuccess(false);
          setQuizAnswer('');
        }, 2000);
      } catch (err) {
        setQuizError("Erreur de connexion.");
      }
    } else {
      setQuizError("Mauvaise réponse. Réessayez !");
    }
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;

    setIsAnalyzing(true);
    setResult(null);
    setError('');
    setSandboxImage(null);
    setUploadResult(null);
    setDetectedBrand(null);
    setShowComparison(false);
    setAnalysisQuizAnswer('');
    setAnalysisQuizFeedback(null);

    // Détection de la marque
    const lowerContent = content.toLowerCase();
    if (lowerContent.includes('microsoft')) setDetectedBrand('microsoft');
    else if (lowerContent.includes('fedex')) setDetectedBrand('fedex');
    else if (lowerContent.includes('amazon')) setDetectedBrand('amazon');
    else if (lowerContent.includes('netflix')) setDetectedBrand('netflix');

    // On fait tourner les étapes en arrière-plan sans bloquer
    let currentStep = 0;
    const interval = setInterval(() => {
      setAnalysisStep(SCAN_STEPS[currentStep % SCAN_STEPS.length]);
      currentStep++;
    }, 600);

    try {
      // APPEL API DIRECT
      const data = await analysisService.analyze(content);

      clearInterval(interval);
      setResult(data);
      setReportSuccess(false);

      if (toClassification(data) === 'Safe') {
        confetti({ particleCount: 100, spread: 70, origin: { y: 0.6 } });
      }

      // Sandbox asynchrone
      if (content.trim().startsWith('http')) {
        setIsSandboxLoading(true);
        analysisService.sandbox(content.trim())
          .then(res => res.screenshot && setSandboxImage(res.screenshot))
          .catch(err => console.error("Sandbox error:", err))
          .finally(() => setIsSandboxLoading(false));
      }
    } catch (err: any) {
      clearInterval(interval);
      setError(err.response?.data?.detail || err.message || "Erreur de connexion au serveur.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setResult(null);
    setError('');
    setSandboxImage(null);
    setUploadResult(null);

    try {
      const res = await analysisService.uploadFile(file);
      setUploadResult(res);
    } catch (err) {
      setError("Erreur lors de l'analyse du fichier.");
    } finally {
      setIsUploading(false);
    }
  };

  const handleReport = async () => {
    setIsReporting(true);
    try {
      await analysisService.reportPhishing();
      setReportSuccess(true);
      confetti({ particleCount: 150, spread: 100, origin: { y: 0.6 } });
    } catch (err) {
      console.error("Erreur lors du signalement:", err);
    } finally {
      setIsReporting(false);
    }
  };

  const handleAnalysisQuizSubmit = async () => {
    if (!result?.quiz || !analysisQuizAnswer) return;

    setIsSubmittingAnalysisQuiz(true);
    setAnalysisQuizFeedback(null);

    try {
      const feedback = await analysisService.completeQuiz(result.quiz.attack_type, analysisQuizAnswer);
      setAnalysisQuizFeedback(feedback);
      if (feedback.correct) {
        confetti({ particleCount: 120, spread: 80, origin: { y: 0.7 } });
      }

      // Mettre à jour l'état de l'utilisateur dans le contexte de l'application
      if (feedback.xp !== undefined && feedback.vigilance_score !== undefined) {
        updateUser({
          xp: feedback.xp,
          level: feedback.level,
          vigilance_score: feedback.vigilance_score
        });
      }
    } catch (err: any) {
      setAnalysisQuizFeedback({
        correct: false,
        message: err.message || "Impossible de valider le quiz.",
      });
    } finally {
      setIsSubmittingAnalysisQuiz(false);
    }
  };

  const classification = result ? toClassification(result) : null;

  if (isBlocked) {
    return (
      <div className="container mx-auto px-6 py-10 max-w-3xl">
        <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="bg-white dark:bg-slate-900 p-10 rounded-[32px] shadow-2xl border border-red-100 dark:border-red-900/50 text-center">
          <div className="w-20 h-20 bg-red-100 dark:bg-red-900/30 text-red-600 rounded-full flex items-center justify-center mx-auto mb-6">
            <AlertTriangle size={40} />
          </div>
          <h1 className="text-3xl font-black text-slate-900 dark:text-white mb-4">Accès Bloqué</h1>
          <p className="text-lg text-slate-600 dark:text-slate-400 mb-8 leading-relaxed">
            Vous avez cliqué sur plusieurs emails de simulation de phishing. Par mesure de sécurité, l'accès à l'analyseur est suspendu jusqu'à ce que vous complétiez ce module de sensibilisation rapide.
          </p>

          <div className="bg-slate-50 dark:bg-slate-800 p-8 rounded-3xl text-left border border-slate-100 dark:border-slate-700">
            <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-4">Leçon Express : Identifier l'Urgence</h3>
            <p className="text-slate-600 dark:text-slate-400 mb-6">
              Les attaquants créent souvent un sentiment d'urgence ("Votre compte va être supprimé", "Action requise immédiatement") pour vous pousser à agir vite sans vérifier l'expéditeur ou le lien.
            </p>

            <div className="space-y-4 mb-6">
              <p className="font-bold text-slate-900 dark:text-white">Question : Lequel de ces éléments est le signal le plus fort d'un phishing potentiel ?</p>

              <label className={`flex items-center gap-3 p-4 border rounded-xl cursor-pointer transition-all ${quizAnswer === 'logo' ? 'border-brand-500 bg-brand-50 dark:bg-brand-900/20' : 'border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800'}`}>
                <input type="radio" name="quiz" value="logo" checked={quizAnswer === 'logo'} onChange={(e) => setQuizAnswer(e.target.value)} className="w-5 h-5 text-brand-600" />
                <span className="dark:text-white font-medium">Un logo officiel d'une grande marque.</span>
              </label>

              <label className={`flex items-center gap-3 p-4 border rounded-xl cursor-pointer transition-all ${quizAnswer === 'urgence' ? 'border-brand-500 bg-brand-50 dark:bg-brand-900/20' : 'border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800'}`}>
                <input type="radio" name="quiz" value="urgence" checked={quizAnswer === 'urgence'} onChange={(e) => setQuizAnswer(e.target.value)} className="w-5 h-5 text-brand-600" />
                <span className="dark:text-white font-medium">Un message demandant une action urgente sous peine de blocage de compte.</span>
              </label>

              <label className={`flex items-center gap-3 p-4 border rounded-xl cursor-pointer transition-all ${quizAnswer === 'nom' ? 'border-brand-500 bg-brand-50 dark:bg-brand-900/20' : 'border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800'}`}>
                <input type="radio" name="quiz" value="nom" checked={quizAnswer === 'nom'} onChange={(e) => setQuizAnswer(e.target.value)} className="w-5 h-5 text-brand-600" />
                <span className="dark:text-white font-medium">Le fait que l'email vous appelle par votre prénom.</span>
              </label>
            </div>

            {quizError && <p className="text-red-500 font-bold mb-4">{quizError}</p>}

            <button
              onClick={handleQuizSubmit}
              disabled={!quizAnswer || quizSuccess}
              className={`w-full py-4 rounded-xl font-bold flex items-center justify-center gap-2 transition-all ${quizSuccess ? 'bg-emerald-500 text-white' : 'bg-brand-600 text-white hover:bg-brand-700 disabled:opacity-50'}`}
            >
              {quizSuccess ? <><CheckCircle2 size={20} /> Excellent ! Accès débloqué...</> : "Valider ma réponse"}
            </button>
          </div>
        </motion.div>
      </div>
    );
  }

  // Fonction d'highlighting interactive
  const renderInteractiveHighlight = (text: string) => {
    if (!text) return null;

    let html = text;
    const placeholders: string[] = [];

    // First protect URLs
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    html = html.replace(urlRegex, (url) => {
      const id = placeholders.length;
      placeholders.push(`<span class="bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-400 px-1.5 py-0.5 rounded underline decoration-2 font-mono text-xs break-all">${url}</span>`);
      return `__PH_${id}__`;
    });

    const applyHighlight = (words: string[], tooltip: string, className: string) => {
      words.forEach(word => {
        // Regex boundaries
        const regex = new RegExp(`\\b(${word})\\b`, "gi");
        html = html.replace(regex, (match) => {
          const id = placeholders.length;
          placeholders.push(`<span class="group relative cursor-help inline-block mx-[1px]">
            <span class="${className}">${match}</span>
            <span class="pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-max max-w-[220px] opacity-0 group-hover:opacity-100 transition-opacity bg-slate-800 text-white text-xs p-2 rounded-lg shadow-xl z-10 border border-slate-700 text-center leading-tight">
              ${tooltip}
              <svg class="absolute text-slate-800 h-2 w-full left-0 top-full" x="0px" y="0px" viewBox="0 0 255 255" xml:space="preserve"><polygon class="fill-current" points="0,0 127.5,127.5 255,0"/></svg>
            </span>
          </span>`);
          return `__PH_${id}__`;
        });
      });
    };

    applyHighlight(["urgent", "immédiat", "24h", "suspendu", "clôture", "vite", "maintenant", "action requise"], "Pression temporelle : vous pousse à agir vite", "bg-red-200 dark:bg-red-900/40 text-red-800 dark:text-red-200 px-1.5 rounded border-b-2 border-red-500 font-bold");
    applyHighlight(["cadeau", "gagner", "prix", "gratuit", "loterie", "sélectionné", "chanceux", "félicitations"], "Appât du gain : promesse souvent fausse", "bg-amber-200 dark:bg-amber-900/40 text-amber-800 dark:text-amber-200 px-1.5 rounded border-b-2 border-amber-500 font-bold");
    applyHighlight(["lidl", "amazon", "microsoft", "paypal", "netflix", "ameli", "fedex", "chronopost", "office365"], "Usurpation : tentative d'imiter une entité connue", "bg-purple-200 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200 px-1.5 rounded border-b-2 border-purple-500 font-bold");

    // Restore placeholders
    placeholders.forEach((replacement, index) => {
      html = html.replace(new RegExp(`__PH_${index}__`, "g"), replacement);
    });

    return (
      <div
        className="whitespace-pre-wrap leading-relaxed text-slate-700 dark:text-slate-300 text-[15px]"
        dangerouslySetInnerHTML={{ __html: html }}
      />
    );
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, x: -20 },
    show: { opacity: 1, x: 0 }
  };

  return (
    <div className="container mx-auto px-6 py-10 max-w-4xl relative">
      <div className="mb-10 text-center">
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white">Analyseur de Contenu IA</h1>
        <p className="text-slate-500 dark:text-slate-400 mt-2">Collez un email, un SMS ou un lien pour une vérification approfondie.</p>
      </div>

      <div className="bg-white dark:bg-slate-900 p-8 rounded-3xl shadow-sm border border-slate-100 dark:border-slate-800 mb-8 transition-colors">
        <form onSubmit={handleAnalyze}>
          <div className="mb-6">
            <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">Contenu à analyser</label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              className="w-full h-48 p-4 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none transition-all resize-none dark:text-white"
              placeholder="Collez ici le texte suspect, ou une URL pour voir la Safe-Link Sandbox..."
            />
          </div>

          <div className="mb-6 flex flex-col items-center justify-center w-full">
            <label className="flex flex-col items-center justify-center w-full h-24 border-2 border-slate-300 border-dashed rounded-xl cursor-pointer bg-slate-50 dark:hover:bg-bray-800 dark:bg-slate-800 hover:bg-slate-100 dark:border-slate-600 dark:hover:border-slate-500 dark:hover:bg-slate-700 transition-all">
              <div className="flex flex-col items-center justify-center pt-5 pb-6">
                <p className="mb-2 text-sm text-slate-500 dark:text-slate-400 font-semibold">
                  <span className="font-bold text-brand-600">Cliquez pour uploader</span> ou glissez un fichier .eml / .msg
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">Analyse SPF/DKIM et Metadata</p>
              </div>
              <input type="file" accept=".eml,.msg,.txt" className="hidden" onChange={handleFileUpload} disabled={isUploading} />
            </label>
            {isUploading && <p className="text-sm font-bold text-brand-600 mt-2 animate-pulse">Analyse du fichier en cours...</p>}
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl text-red-700 dark:text-red-400 text-sm font-medium text-center">
              {error}
            </div>
          )}

          {!isAnalyzing ? (
            <button
              type="submit"
              disabled={!content.trim()}
              className="w-full py-4 bg-brand-600 text-white rounded-xl font-semibold hover:bg-brand-700 transition-all flex items-center justify-center gap-2 disabled:opacity-70 shadow-lg shadow-brand-200/50 neo-button"
            >
              Lancer l'audit de sécurité <Search size={20} />
            </button>
          ) : (
            <div className="w-full py-6 bg-slate-50 dark:bg-slate-800 rounded-xl border border-brand-200 dark:border-brand-900/50 flex flex-col items-center justify-center relative overflow-hidden">
              <div className="absolute top-0 left-0 h-1 bg-brand-500 transition-all duration-300" style={{ width: `${((SCAN_STEPS.indexOf(analysisStep) + 1) / SCAN_STEPS.length) * 100}%` }}></div>
              <Loader2 className="animate-spin text-brand-600 mb-3" size={32} />
              <p className="text-brand-700 dark:text-brand-400 font-bold animate-pulse">{analysisStep}</p>
              <div className="flex gap-1 mt-4">
                {SCAN_STEPS.map((step, idx) => (
                  <div key={idx} className={`h-1.5 rounded-full transition-all duration-300 ${SCAN_STEPS.indexOf(analysisStep) >= idx ? 'w-6 bg-brand-500' : 'w-2 bg-slate-300 dark:bg-slate-600'}`} />
                ))}
              </div>
            </div>
          )}
        </form>
      </div>

      <AnimatePresence>
        {uploadResult && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="mb-8"
          >
            <div className={`p-8 rounded-3xl border flex items-center gap-6 ${uploadResult.is_verified ? 'bg-emerald-50 border-emerald-100 dark:bg-emerald-900/20 dark:border-emerald-800' : 'bg-red-50 border-red-100 dark:bg-red-900/20 dark:border-red-800'}`}>
              <div className={`w-16 h-16 rounded-full flex items-center justify-center shrink-0 ${uploadResult.is_verified ? 'bg-emerald-200 text-emerald-700' : 'bg-red-200 text-red-700'}`}>
                {uploadResult.is_verified ? <CheckCircle2 size={32} /> : <AlertTriangle size={32} />}
              </div>
              <div>
                <h2 className={`text-xl font-bold ${uploadResult.is_verified ? 'text-emerald-900 dark:text-emerald-100' : 'text-red-900 dark:text-red-100'}`}>
                  {uploadResult.message}
                </h2>
                <p className="text-sm font-medium text-slate-600 dark:text-slate-400 mt-1">
                  Fichier : {uploadResult.filename}
                </p>
                <div className="flex gap-4 mt-3">
                  <span className={`px-2 py-1 rounded text-xs font-bold ${uploadResult.spf_pass ? 'bg-emerald-200 text-emerald-800' : 'bg-red-200 text-red-800'}`}>SPF: {uploadResult.spf_pass ? 'PASS' : 'FAIL'}</span>
                  <span className={`px-2 py-1 rounded text-xs font-bold ${uploadResult.dkim_pass ? 'bg-emerald-200 text-emerald-800' : 'bg-red-200 text-red-800'}`}>DKIM: {uploadResult.dkim_pass ? 'PASS' : 'FAIL'}</span>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {result && classification && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            <div className={`p-8 rounded-3xl border flex flex-col md:flex-row items-center gap-8 shadow-sm ${classification === 'Safe' ? 'bg-emerald-50 dark:bg-emerald-900/10 border-emerald-100 dark:border-emerald-800/50' :
                classification === 'Dangerous' ? 'bg-red-50 dark:bg-red-900/10 border-red-100 dark:border-red-800/50' :
                  'bg-amber-50 dark:bg-amber-900/10 border-amber-100 dark:border-amber-800/50'
              }`}>
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                className={`w-24 h-24 rounded-full flex items-center justify-center shrink-0 shadow-inner ${classification === 'Safe' ? 'bg-emerald-100 dark:bg-emerald-800 text-emerald-600' :
                    classification === 'Dangerous' ? 'bg-red-100 dark:bg-red-800 text-red-600' :
                      'bg-amber-100 dark:bg-amber-800 text-amber-600'
                  }`}
              >
                {classification === 'Safe' ? <CheckCircle2 size={48} /> : <AlertTriangle size={48} />}
              </motion.div>
              <div className="text-center md:text-left flex-1">
                <div className="flex items-center justify-center md:justify-start gap-3 mb-2">
                  <h2 className={`text-3xl font-black tracking-tight ${classification === 'Safe' ? 'text-emerald-900 dark:text-emerald-100' :
                      classification === 'Dangerous' ? 'text-red-900 dark:text-red-100' : 'text-amber-900 dark:text-amber-100'
                    }`}>
                    {classification === 'Safe' ? 'Contenu Sûr' : classification === 'Dangerous' ? 'Menace Critique' : 'Contenu Suspect'}
                  </h2>
                  <span className={`px-4 py-1 rounded-full text-sm font-black shadow-sm ${classification === 'Safe' ? 'bg-emerald-200 text-emerald-800' :
                      classification === 'Dangerous' ? 'bg-red-500 text-white' : 'bg-amber-400 text-amber-900'
                    }`}>
                    Score ML: {(result.final_score ?? result.confidence).toFixed(0)}/100
                  </span>
                </div>
                <p className={`text-lg font-medium ${classification === 'Safe' ? 'text-emerald-700 dark:text-emerald-300' :
                    classification === 'Dangerous' ? 'text-red-700 dark:text-red-300' : 'text-amber-700 dark:text-amber-300'
                  }`}>
                  Probabilité de phishing : <strong>{(result.probability * 100).toFixed(1)}%</strong>.{' '}
                  {classification === 'Safe' ? "Aucun pattern malveillant n'a été détecté par l'IA." : "Des caractéristiques de phishing ont été identifiées."}
                </p>
              </div>
            </div>

            <div className="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-100 dark:border-slate-800 shadow-sm">
              <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-5">
                <div>
                  <h3 className="text-lg font-black text-slate-900 dark:text-white">Lecture multi-moteurs</h3>
                  <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                    La décision finale reste basée sur le ML. La couche IA sert à expliquer et orienter la formation.
                  </p>
                </div>
                {result.engine_disagreement && (
                  <span className="inline-flex items-center gap-2 px-3 py-2 rounded-xl bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300 text-sm font-bold">
                    <AlertTriangle size={16} /> Désaccord détecté
                  </span>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-800 border border-slate-100 dark:border-slate-700">
                  <p className="text-xs uppercase font-black text-slate-400 tracking-widest">ML</p>
                  <p className="text-2xl font-black text-slate-900 dark:text-white mt-1">{(result.ml_score ?? result.confidence).toFixed(0)}/100</p>
                </div>
                <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-800 border border-slate-100 dark:border-slate-700">
                  <p className="text-xs uppercase font-black text-slate-400 tracking-widest">IA explicative</p>
                  <p className="text-2xl font-black text-slate-900 dark:text-white mt-1">{(result.llm_score ?? 0).toFixed(0)}/100</p>
                </div>
                <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-800 border border-slate-100 dark:border-slate-700">
                  <p className="text-xs uppercase font-black text-slate-400 tracking-widest">Attaque</p>
                  <p className="text-base font-black text-slate-900 dark:text-white mt-2">{result.attack_type || 'Unknown'}</p>
                </div>
              </div>

              {(result.techniques?.length || result.recommended_training?.length) && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                  <div>
                    <p className="text-xs uppercase font-black text-slate-400 tracking-widest mb-2">Techniques</p>
                    <div className="flex flex-wrap gap-2">
                      {(result.techniques || []).map((technique) => (
                        <span key={technique} className="px-3 py-1 rounded-lg bg-brand-50 dark:bg-brand-900/20 text-brand-700 dark:text-brand-300 text-sm font-bold">
                          {technique}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs uppercase font-black text-slate-400 tracking-widest mb-2">Formation conseillée</p>
                    <div className="flex flex-wrap gap-2">
                      {(result.recommended_training || []).map((training) => (
                        <button
                          key={training}
                          type="button"
                          onClick={() => setSelectedTraining(training)}
                          className="px-3 py-1 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300 text-sm font-bold hover:bg-emerald-100 dark:hover:bg-emerald-900/40 transition-colors cursor-pointer text-left"
                        >
                          {training}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {result.quiz && (
              <div className="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-100 dark:border-slate-800 shadow-sm">
                <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4 mb-5">
                  <div>
                    <h3 className="text-lg font-black text-slate-900 dark:text-white">Mini quiz vigilance</h3>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                      Répondez pour gagner {result.quiz.xp_reward} XP et améliorer votre vigilance.
                    </p>
                  </div>
                  <span className="px-3 py-2 rounded-xl bg-brand-50 dark:bg-brand-900/20 text-brand-700 dark:text-brand-300 text-sm font-bold">
                    {result.quiz.attack_type || 'Training'}
                  </span>
                </div>

                <p className="font-bold text-slate-900 dark:text-white mb-4">{result.quiz.question}</p>

                <div className="space-y-3">
                  {result.quiz.options.map((option) => (
                    <label
                      key={option}
                      className={`flex items-center gap-3 p-4 border rounded-xl cursor-pointer transition-all ${
                        analysisQuizAnswer === option
                          ? 'border-brand-500 bg-brand-50 dark:bg-brand-900/20'
                          : 'border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800'
                      } ${analysisQuizFeedback ? 'cursor-default' : ''}`}
                    >
                      <input
                        type="radio"
                        name="analysis-quiz"
                        value={option}
                        checked={analysisQuizAnswer === option}
                        onChange={(e) => setAnalysisQuizAnswer(e.target.value)}
                        disabled={!!analysisQuizFeedback}
                        className="w-5 h-5 text-brand-600"
                      />
                      <span className="dark:text-white font-medium">{option}</span>
                    </label>
                  ))}
                </div>

                {analysisQuizFeedback && (
                  <div className={`mt-4 p-4 rounded-xl border ${
                    analysisQuizFeedback.correct
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-800 dark:bg-emerald-900/20 dark:border-emerald-800 dark:text-emerald-300'
                      : 'bg-red-50 border-red-200 text-red-800 dark:bg-red-900/20 dark:border-red-800 dark:text-red-300'
                  }`}>
                    <p className="font-bold">{analysisQuizFeedback.message}</p>
                    {!analysisQuizFeedback.correct && analysisQuizFeedback.correct_answer && (
                      <p className="text-sm font-semibold mt-1">Bonne réponse : <span className="underline">{analysisQuizFeedback.correct_answer}</span></p>
                    )}
                    <p className="text-sm mt-2 font-medium">
                      {analysisQuizFeedback.correct ? `+${analysisQuizFeedback.xp_awarded} XP` : '0 XP'} · Vigilance : {analysisQuizFeedback.vigilance_score?.toFixed?.(0) ?? analysisQuizFeedback.vigilance_score}/100 ({analysisQuizFeedback.vigilance_delta > 0 ? `+${analysisQuizFeedback.vigilance_delta}` : analysisQuizFeedback.vigilance_delta}) · Niveau : {analysisQuizFeedback.level}
                    </p>
                  </div>
                )}

                {!analysisQuizFeedback && (
                  <button
                    onClick={handleAnalysisQuizSubmit}
                    disabled={!analysisQuizAnswer || isSubmittingAnalysisQuiz}
                    className="mt-5 w-full sm:w-auto px-6 py-3 bg-brand-600 text-white rounded-xl font-bold hover:bg-brand-700 disabled:opacity-60 transition-all flex items-center justify-center gap-2"
                  >
                    {isSubmittingAnalysisQuiz ? <Loader2 className="animate-spin" size={18} /> : <CheckCircle2 size={18} />}
                    Valider le quiz
                  </button>
                )}
              </div>
            )}

            {classification !== 'Safe' && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Bloc 1: Le texte highlighté interactif */}
                <div className="bg-slate-50 dark:bg-slate-800/80 p-6 rounded-3xl border border-slate-200 dark:border-slate-700">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                    <Eye size={14} /> Traces détectées (Survolez les mots)
                  </h4>
                  <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-100 dark:border-slate-800 shadow-inner">
                    {renderInteractiveHighlight(content)}
                  </div>
                </div>

                {/* Bloc 2: Explications en cascade */}
                <div className="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-100 dark:border-slate-800 shadow-sm">
                  <h3 className="text-lg font-black text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                    <AlertTriangle className={classification === 'Dangerous' ? "text-red-500" : "text-amber-500"} size={20} />
                    Rapport Détaillé
                  </h3>
                  
                  <motion.div variants={containerVariants} initial="hidden" animate="show" className="space-y-4">
                    {result.explanation && result.explanation.map((reason, index) => (
                      <motion.div 
                        key={index}
                        variants={itemVariants}
                        className="group relative flex items-start gap-4 p-5 bg-gradient-to-br from-slate-50 to-white dark:from-slate-800/80 dark:to-slate-900 rounded-2xl border border-slate-200/60 dark:border-slate-700/50 shadow-sm hover:shadow-md hover:border-slate-300 dark:hover:border-slate-600 transition-all duration-300 overflow-hidden"
                      >
                        {/* Ligne d'accentuation dynamique */}
                        <div className={`absolute top-0 left-0 w-1 h-full rounded-l-2xl transition-all duration-300 group-hover:w-1.5 ${classification === 'Dangerous' ? 'bg-red-500' : 'bg-amber-500'}`} />
                        
                        {/* Effet de lueur au survol */}
                        <div className={`absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 ${classification === 'Dangerous' ? 'bg-gradient-to-r from-red-50/50 to-transparent dark:from-red-900/10' : 'bg-gradient-to-r from-amber-50/50 to-transparent dark:from-amber-900/10'}`} />

                        {/* Icône */}
                        <div className={`relative shrink-0 w-8 h-8 rounded-full flex items-center justify-center border mt-0.5 transition-transform duration-300 group-hover:scale-110 shadow-sm ${classification === 'Dangerous' ? 'bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800/50' : 'bg-amber-50 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-800/50'}`}>
                          <AlertTriangle size={14} strokeWidth={2.5} />
                        </div>

                        {/* Contenu textuel */}
                        <div className="flex-1 relative z-10">
                          {reason.split('**').map((part, i) => {
                            if (i % 2 === 1) {
                              return (
                                <h4 key={i} className="text-slate-900 dark:text-white font-bold text-[15px] mb-1">
                                  {part}
                                </h4>
                              );
                            }
                            const text = part.replace(/^[\s:]+/, '');
                            if (!text) return null;
                            return (
                              <p key={i} className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                                {text}
                              </p>
                            );
                          })}
                        </div>
                      </motion.div>
                    ))}
                  </motion.div>
                </div>
              </div>
            )}

            {/* Sandbox Render Amélioré */}
            {(isSandboxLoading || sandboxImage) && (
              <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900 rounded-3xl overflow-hidden border-2 border-slate-700 shadow-2xl relative mt-8">
                <div className="bg-slate-800 px-4 py-3 flex justify-between items-center border-b border-slate-700">
                  <div className="flex gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500"></div>
                    <div className="w-3 h-3 rounded-full bg-amber-500"></div>
                    <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
                  </div>
                  <div className="text-xs font-bold text-slate-300 bg-slate-900 px-4 py-1 rounded-full flex items-center gap-2">
                    <Search size={12} className="text-brand-400" /> Safe-Link Sandbox
                  </div>
                  <div className="w-12"></div> {/* Spacer for center alignment */}
                </div>

                <div className="p-0 min-h-[300px] flex flex-col items-center justify-center relative bg-slate-100 dark:bg-slate-950 overflow-hidden">
                  {isSandboxLoading ? (
                    <div className="text-center text-slate-500 flex flex-col items-center py-20">
                      <Loader2 className="animate-spin mb-4 text-brand-500" size={40} />
                      <span className="font-bold text-sm tracking-wide">Environnement isolé en cours de création...</span>
                    </div>
                  ) : sandboxImage ? (
                    <div className="relative group cursor-zoom-in w-full h-full flex justify-center bg-slate-200 dark:bg-slate-900 p-4" onClick={() => setIsLightboxOpen(true)}>
                      <img src={sandboxImage} alt="Sandbox preview" className="w-full h-auto max-h-[500px] object-contain shadow-lg rounded transition-transform duration-500 group-hover:scale-[1.02]" />
                      <div className="absolute inset-0 bg-slate-900/40 opacity-0 group-hover:opacity-100 transition-opacity duration-300 flex items-center justify-center backdrop-blur-[2px]">
                        <div className="bg-white/20 p-4 rounded-full backdrop-blur-md">
                          <ZoomIn className="text-white w-10 h-10" />
                        </div>
                      </div>
                    </div>
                  ) : null}
                  <div className="absolute top-4 right-4 bg-amber-500/90 backdrop-blur text-white text-[10px] font-black uppercase px-3 py-1.5 rounded-md shadow-lg border border-amber-400">Navigation Isolée</div>
                </div>

                {detectedBrand && sandboxImage && !isSandboxLoading && (
                  <div className="bg-slate-800 p-4 border-t border-slate-700 flex justify-center">
                    <button
                      onClick={() => setShowComparison(true)}
                      className="flex items-center gap-2 px-6 py-2.5 bg-brand-600 hover:bg-brand-500 text-white rounded-xl font-bold transition-colors shadow-lg"
                    >
                      <Eye size={18} />
                      Comparer avec le site officiel de {detectedBrand.charAt(0).toUpperCase() + detectedBrand.slice(1)}
                    </button>
                  </div>
                )}
              </motion.div>
            )}

            <div className="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-100 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row gap-6 justify-between items-start sm:items-center mt-6">
              <div>
                <h3 className="font-bold mb-3 flex items-center gap-2 text-slate-900 dark:text-white">
                  <Info size={18} className="text-brand-600" /> Conseil de sécurité
                </h3>
                <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed max-w-xl">
                  {classification === 'Safe'
                    ? "Même si ce message semble sûr, restez vigilant. Ne partagez jamais vos mots de passe par email."
                    : "Ne cliquez sur aucun lien, ne répondez pas et signalez ce message à votre service informatique immédiatement."}
                </p>
              </div>

              {classification !== 'Safe' && (
                <button
                  onClick={handleReport}
                  disabled={isReporting || reportSuccess}
                  className={`shrink-0 px-6 py-4 rounded-xl font-bold flex items-center gap-2 transition-all shadow-md ${reportSuccess
                      ? 'bg-emerald-500 text-white hover:bg-emerald-600'
                      : 'bg-red-100 text-red-700 hover:bg-red-200 dark:bg-red-900/30 dark:text-red-400 dark:hover:bg-red-900/50'
                    }`}
                >
                  {reportSuccess ? (
                    <><CheckCircle2 size={20} /> Signalé (+10 XP) !</>
                  ) : (
                    <><AlertTriangle size={20} /> Signaler à l'IT</>
                  )}
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Lightbox Modals */}
      <AnimatePresence>
        {isLightboxOpen && sandboxImage && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-slate-900/95 backdrop-blur-sm flex items-center justify-center p-4 cursor-zoom-out"
            onClick={() => setIsLightboxOpen(false)}
          >
            <button className="absolute top-6 right-6 text-slate-400 hover:text-white transition-colors bg-slate-800/50 p-2 rounded-full"><X size={32} /></button>
            <motion.img
              initial={{ scale: 0.9 }}
              animate={{ scale: 1 }}
              src={sandboxImage}
              alt="Sandbox fullscreen"
              className="max-w-full max-h-[90vh] rounded-xl shadow-2xl border border-slate-700 cursor-default"
              onClick={e => e.stopPropagation()}
            />
          </motion.div>
        )}

        {showComparison && detectedBrand && sandboxImage && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-slate-900/95 backdrop-blur-md flex flex-col items-center justify-center p-6"
            onClick={() => setShowComparison(false)}
          >
            <button className="absolute top-6 right-6 text-slate-400 hover:text-white transition-colors bg-slate-800/50 p-2 rounded-full"><X size={32} /></button>

            <h2 className="text-white text-3xl font-black mb-8 flex items-center gap-3">
              <Eye className="text-brand-500" size={32} />
              Analyse Visuelle : <span className="text-brand-400 capitalize">{detectedBrand}</span>
            </h2>

            <div className="flex flex-col md:flex-row gap-8 w-full max-w-7xl h-[70vh] cursor-default" onClick={e => e.stopPropagation()}>
              {/* Suspect */}
              <div className="flex-1 flex flex-col">
                <div className="bg-red-500/20 border border-red-500/50 text-red-200 font-bold py-3 px-4 rounded-t-xl text-center flex justify-center items-center gap-2">
                  <AlertTriangle size={18} /> Site Suspect (Capture Sandbox)
                </div>
                <div className="flex-1 bg-slate-800 rounded-b-xl overflow-hidden border-x border-b border-red-500/50 flex items-center justify-center p-2">
                  <img src={sandboxImage} className="max-w-full max-h-full object-contain" />
                </div>
              </div>

              {/* Real */}
              <div className="flex-1 flex flex-col">
                <div className="bg-emerald-500/20 border border-emerald-500/50 text-emerald-200 font-bold py-3 px-4 rounded-t-xl text-center flex justify-center items-center gap-2">
                  <CheckCircle2 size={18} /> Site Officiel ({detectedBrand})
                </div>
                <div className="flex-1 bg-slate-800 rounded-b-xl overflow-hidden border-x border-b border-emerald-500/50 flex items-center justify-center p-2 relative">
                  {/* Fallback en cas d'image manquante pour la démo */}
                  <img src={`/${detectedBrand}_real.png`} alt={`Vrai site ${detectedBrand}`} className="max-w-full max-h-full object-contain" onError={(e) => {
                    (e.target as HTMLImageElement).style.display = 'none';
                    (e.target as HTMLImageElement).parentElement!.innerHTML = '<div class="text-slate-400 text-center"><p class="mb-2">Image de référence non trouvée localement.</p><p class="text-sm">Assurez-vous que <code>/' + detectedBrand + '_real.png</code> est dans le dossier public.</p></div>';
                  }} />
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Training Modal */}
      <AnimatePresence>
        {selectedTraining && (() => {
          const trainingData = TRAINING_CONTENTS[selectedTraining] || TRAINING_CONTENTS["Bonnes pratiques de vigilance email"];
          
          let icon = <Info size={32} className="text-brand-600" />;
          if (trainingData.iconType === 'urgency') icon = <AlertTriangle size={32} className="text-red-500" />;
          else if (trainingData.iconType === 'authority') icon = <ShieldAlert size={32} className="text-amber-500" />;
          else if (trainingData.iconType === 'credential') icon = <Lock size={32} className="text-indigo-500" />;
          else if (trainingData.iconType === 'brand') icon = <Eye size={32} className="text-purple-500" />;
          else if (trainingData.iconType === 'link') icon = <MousePointerClick size={32} className="text-emerald-500" />;
          else if (trainingData.iconType === 'high_risk') icon = <AlertTriangle size={32} className="text-rose-500" />;
          else if (trainingData.iconType === 'extortion') icon = <ShieldAlert size={32} className="text-orange-500" />;
          
          return (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4"
              onClick={() => setSelectedTraining(null)}
            >
              <motion.div
                initial={{ scale: 0.95, y: 20 }}
                animate={{ scale: 1, y: 0 }}
                exit={{ scale: 0.95, y: 20 }}
                className="bg-white dark:bg-slate-900 w-full max-w-xl p-8 rounded-[32px] shadow-2xl border border-slate-100 dark:border-slate-800"
                onClick={e => e.stopPropagation()}
              >
                <div className="flex items-start gap-4 mb-6">
                  <div className="w-14 h-14 bg-slate-50 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0 shadow-inner">
                    {icon}
                  </div>
                  <div>
                    <span className="text-[10px] font-bold text-brand-600 dark:text-brand-400 uppercase tracking-widest">Formation Cybersécurité</span>
                    <h3 className="text-2xl font-black text-slate-900 dark:text-white mt-1">{trainingData.title}</h3>
                  </div>
                </div>

                <p className="text-slate-600 dark:text-slate-400 leading-relaxed font-medium mb-6">
                  {trainingData.description}
                </p>

                <div className="bg-slate-50 dark:bg-slate-800 p-6 rounded-2xl border border-slate-100 dark:border-slate-700 mb-6">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">Les bons réflexes à adopter :</h4>
                  <ul className="space-y-4">
                    {trainingData.reflexes.map((reflex, idx) => (
                      <li key={idx} className="flex gap-3 text-sm font-semibold text-slate-700 dark:text-slate-200">
                        <CheckCircle2 size={16} className="text-emerald-500 shrink-0 mt-0.5" />
                        <span>{reflex}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="flex gap-4">
                  <button
                    onClick={() => setSelectedTraining(null)}
                    className="w-full py-4 bg-brand-600 text-white rounded-2xl font-black hover:bg-brand-700 transition-all flex items-center justify-center gap-2 shadow-xl shadow-brand-200/50"
                  >
                    J'ai compris et assimilé !
                  </button>
                </div>
              </motion.div>
            </motion.div>
          );
        })()}
      </AnimatePresence>
    </div>
  );
};
