import { useState, useEffect, useCallback } from 'react'

const TIER_STYLES = {
  LOW: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  MODERATE: 'bg-yellow-100 text-yellow-800 border-yellow-300',
  ELEVATED: 'bg-orange-100 text-orange-800 border-orange-300',
  HIGH: 'bg-red-100 text-red-800 border-red-300',
  CRITICAL: 'bg-red-200 text-red-900 border-red-500',
}

function TierBadge({ tier }) {
  const style = TIER_STYLES[tier] || 'bg-slate-100 text-slate-800 border-slate-300'
  return (
    <span className={`inline-block px-3 py-1 rounded-full text-sm font-semibold border ${style}`}>
      {tier}
    </span>
  )
}

function ClassificationBadge({ classification }) {
  const style =
    classification === 'MALICIOUS'
      ? 'bg-red-100 text-red-800 border-red-300'
      : 'bg-emerald-100 text-emerald-800 border-emerald-300'
  return (
    <span className={`inline-block px-3 py-1 rounded-full text-sm font-semibold border ${style}`}>
      {classification}
    </span>
  )
}

function AnalysisResult({ result }) {
  if (!result) return null
  return (
    <div className="mt-6 border border-slate-200 rounded-lg p-6 bg-white shadow-sm">
      <h3 className="text-lg font-bold mb-4">Threat Assessment</h3>
      <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
        <div>
          <div className="text-slate-500">File</div>
          <div className="font-mono">{result.file_name}</div>
        </div>
        <div>
          <div className="text-slate-500">SHA-256</div>
          <div className="font-mono text-xs break-all">{result.sha256}</div>
        </div>
        <div>
          <div className="text-slate-500">Classification</div>
          <ClassificationBadge classification={result.classification} />
        </div>
        <div>
          <div className="text-slate-500">Threat Level</div>
          <TierBadge tier={result.threat_level} />
        </div>
        <div>
          <div className="text-slate-500">Confidence</div>
          <div className="font-semibold">{(result.malicious_probability * 100).toFixed(2)}%</div>
        </div>
        <div>
          <div className="text-slate-500">Anomaly Score</div>
          <div className="font-semibold">{result.anomaly_score}</div>
        </div>
        {result.predicted_family && (
          <div>
            <div className="text-slate-500">Likely Family</div>
            <div className="font-semibold">{result.predicted_family}</div>
          </div>
        )}
      </div>

      {result.top_contributing_features?.length > 0 && (
        <div>
          <div className="text-slate-500 text-sm mb-2">Top Contributing Features</div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-500 border-b">
                <th className="py-1">Feature</th>
                <th className="py-1">Value</th>
                <th className="py-1">SHAP Impact</th>
                <th className="py-1">Direction</th>
              </tr>
            </thead>
            <tbody>
              {result.top_contributing_features.map((f, i) => (
                <tr key={i} className="border-b border-slate-100">
                  <td className="py-1 font-mono">{f.feature}</td>
                  <td className="py-1">{f.value}</td>
                  <td className={`py-1 font-semibold ${f.shap_value > 0 ? 'text-red-600' : 'text-emerald-600'}`}>
                    {f.shap_value > 0 ? '+' : ''}{f.shap_value}
                  </td>
                  <td className="py-1 text-slate-600">{f.direction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-4 text-xs text-slate-400">
        This is a probabilistic assessment from static analysis only. It is not a
        substitute for professional malware analysis and should not be the sole
        basis for a security decision.
      </p>
    </div>
  )
}

function AnalyzeTab() {
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!file) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const res = await fetch('/api/analyze', { method: 'POST', body: formData })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail || `Request failed (${res.status})`)
      }
      setResult(await res.json())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h2 className="text-xl font-bold mb-1">Analyze Sample</h2>
      <p className="text-slate-500 text-sm mb-4">
        Static analysis only — the file is never executed.
      </p>
      <form onSubmit={handleSubmit} className="flex items-center gap-3">
        <input
          type="file"
          onChange={(e) => setFile(e.target.files[0])}
          className="text-sm"
        />
        <button
          type="submit"
          disabled={!file || loading}
          className="bg-slate-900 text-white px-4 py-2 rounded-md text-sm font-semibold disabled:opacity-40"
        >
          {loading ? 'Analyzing…' : 'Analyze'}
        </button>
      </form>

      {error && (
        <div className="mt-4 text-red-700 bg-red-50 border border-red-200 rounded-md p-3 text-sm">
          {error}
        </div>
      )}

      <AnalysisResult result={result} />
    </div>
  )
}

function HistoryTab() {
  const [analyses, setAnalyses] = useState([])
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    fetch('/api/analyses')
      .then((r) => r.json())
      .then(setAnalyses)
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold">Analysis History</h2>
        <button onClick={load} className="text-sm text-slate-500 hover:text-slate-900">
          Refresh
        </button>
      </div>

      {loading ? (
        <p className="text-slate-500 text-sm">Loading…</p>
      ) : analyses.length === 0 ? (
        <p className="text-slate-500 text-sm">No analyses yet — run one in the Analyze tab.</p>
      ) : (
        <table className="w-full text-sm bg-white border border-slate-200 rounded-lg overflow-hidden">
          <thead>
            <tr className="text-left bg-slate-50 border-b border-slate-200">
              <th className="py-2 px-3">File</th>
              <th className="py-2 px-3">Classification</th>
              <th className="py-2 px-3">Threat Level</th>
              <th className="py-2 px-3">Confidence</th>
              <th className="py-2 px-3">When</th>
            </tr>
          </thead>
          <tbody>
            {analyses.map((a) => (
              <tr
                key={a.analysis_id}
                onClick={() => setSelected(a)}
                className="border-b border-slate-100 cursor-pointer hover:bg-slate-50"
              >
                <td className="py-2 px-3 font-mono">{a.file_name}</td>
                <td className="py-2 px-3"><ClassificationBadge classification={a.classification} /></td>
                <td className="py-2 px-3"><TierBadge tier={a.threat_level} /></td>
                <td className="py-2 px-3">{(a.malicious_probability * 100).toFixed(2)}%</td>
                <td className="py-2 px-3 text-slate-500">
                  {a.created_at ? new Date(a.created_at).toLocaleString() : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <AnalysisResult result={selected} />
    </div>
  )
}

function StatisticsTab() {
  const [stats, setStats] = useState(null)

  useEffect(() => {
    fetch('/api/statistics').then((r) => r.json()).then(setStats)
  }, [])

  if (!stats) return <p className="text-slate-500 text-sm">Loading…</p>

  return (
    <div>
      <h2 className="text-xl font-bold mb-4">Dashboard</h2>
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <div className="text-slate-500 text-sm">Total Analyses</div>
          <div className="text-2xl font-bold">{stats.total_analyses}</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <div className="text-slate-500 text-sm">Malicious</div>
          <div className="text-2xl font-bold text-red-600">{stats.malicious}</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <div className="text-slate-500 text-sm">Benign</div>
          <div className="text-2xl font-bold text-emerald-600">{stats.benign}</div>
        </div>
      </div>

      <h3 className="font-semibold mb-2 text-sm text-slate-500">Threat Level Distribution</h3>
      <div className="flex gap-2 flex-wrap">
        {Object.entries(stats.threat_level_distribution || {}).map(([tier, count]) => (
          <div key={tier} className="bg-white border border-slate-200 rounded-lg p-3 flex items-center gap-2">
            <TierBadge tier={tier} />
            <span className="font-bold">{count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function ModelsTab() {
  const [models, setModels] = useState(null)

  useEffect(() => {
    fetch('/api/models').then((r) => r.json()).then(setModels)
  }, [])

  if (!models) return <p className="text-slate-500 text-sm">Loading…</p>

  return (
    <div>
      <h2 className="text-xl font-bold mb-4">Models</h2>
      <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-2 text-sm">
        <div><span className="text-slate-500">Malware Detector:</span> {models.malware_detector}</div>
        <div><span className="text-slate-500">Anomaly Detector:</span> {models.anomaly_detector}</div>
        <div><span className="text-slate-500">Family Classifier:</span> {models.family_classifier || 'Not available'}</div>
        <div className="pt-2 text-xs text-slate-400 border-t border-slate-100 mt-2">
          {models.training_scope}
        </div>
      </div>
    </div>
  )
}

const TABS = [
  { id: 'dashboard', label: 'Dashboard', component: StatisticsTab },
  { id: 'analyze', label: 'Analyze Sample', component: AnalyzeTab },
  { id: 'history', label: 'History', component: HistoryTab },
  { id: 'models', label: 'Models', component: ModelsTab },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const ActiveComponent = TABS.find((t) => t.id === activeTab).component

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="bg-slate-900 text-white px-6 py-4">
        <h1 className="text-lg font-bold">ThreatLens</h1>
        <p className="text-slate-400 text-xs">
          AI-Powered Malware Intelligence — static analysis only, never executes files
        </p>
      </header>

      <nav className="bg-white border-b border-slate-200 px-6 flex gap-1">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-3 text-sm font-medium border-b-2 transition ${
              activeTab === tab.id
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="max-w-4xl mx-auto px-6 py-8">
        <ActiveComponent />
      </main>
    </div>
  )
}