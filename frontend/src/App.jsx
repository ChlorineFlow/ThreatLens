import { useState, useEffect, useCallback } from 'react'
import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, LineChart, Line,
} from 'recharts'
import ParticleBackground from './components/ParticleBackground'
import ThemeToggle from './components/ThemeToggle'
import GraphTab from './components/GraphTab'

const TIER_STYLES = {
  LOW: 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800',
  MODERATE: 'bg-yellow-100 text-yellow-800 border-yellow-300 dark:bg-yellow-950 dark:text-yellow-300 dark:border-yellow-800',
  ELEVATED: 'bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-950 dark:text-orange-300 dark:border-orange-800',
  HIGH: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950 dark:text-red-300 dark:border-red-800',
  CRITICAL: 'bg-red-200 text-red-900 border-red-500 dark:bg-red-900 dark:text-red-200 dark:border-red-500',
}

function TierBadge({ tier }) {
  const style = TIER_STYLES[tier] || 'bg-ink-muted/10 text-ink-muted border-border'
  return (
    <span className={`inline-block px-3 py-1 rounded-full text-sm font-semibold border font-display ${style}`}>
      {tier}
    </span>
  )
}

function ClassificationBadge({ classification }) {
  const style =
    classification === 'MALICIOUS'
      ? 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950 dark:text-red-300 dark:border-red-800'
      : 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800'
  return (
    <span className={`inline-block px-3 py-1 rounded-full text-sm font-semibold border font-display ${style}`}>
      {classification}
    </span>
  )
}

function SectionLabel({ children }) {
  return (
    <div className="font-display text-signal text-xs tracking-wider mb-2">
      // {children}
    </div>
  )
}

function Card({ children, className = '' }) {
  return (
    <div className={`bg-surface/90 backdrop-blur border border-border rounded-lg ${className}`}>
      {children}
    </div>
  )
}

function AnalysisResult({ result }) {
  if (!result) return null
  return (
    <Card className="mt-6 p-6 shadow-sm">
      <SectionLabel>threat_assessment</SectionLabel>
      <h3 className="text-lg font-bold font-display mb-4 text-ink">Result</h3>
      <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
        <div>
          <div className="text-ink-muted">File</div>
          <div className="font-display text-ink">{result.file_name}</div>
        </div>
        <div>
          <div className="text-ink-muted">SHA-256</div>
          <div className="font-display text-xs break-all text-ink">{result.sha256}</div>
        </div>
        <div>
          <div className="text-ink-muted">Classification</div>
          <ClassificationBadge classification={result.classification} />
        </div>
        <div>
          <div className="text-ink-muted">Threat Level</div>
          <TierBadge tier={result.threat_level} />
        </div>
        <div>
          <div className="text-ink-muted">Confidence</div>
          <div className="font-semibold font-display text-ink">
            {(result.malicious_probability * 100).toFixed(2)}%
          </div>
        </div>
        <div>
          <div className="text-ink-muted">Anomaly Score</div>
          <div className="font-semibold font-display text-ink">{result.anomaly_score}</div>
        </div>
        {result.predicted_family && (
          <div>
            <div className="text-ink-muted">Likely Family</div>
            <div className="font-semibold font-display text-ink">{result.predicted_family}</div>
          </div>
        )}
      </div>

      {result.top_contributing_features?.length > 0 && (
        <div>
          <div className="text-ink-muted text-sm mb-2">Top Contributing Features</div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-ink-muted border-b border-border font-display">
                <th className="py-1 font-medium">Feature</th>
                <th className="py-1 font-medium">Value</th>
                <th className="py-1 font-medium">SHAP Impact</th>
                <th className="py-1 font-medium">Direction</th>
              </tr>
            </thead>
            <tbody>
              {result.top_contributing_features.map((f, i) => (
                <tr key={i} className="border-b border-border/60">
                  <td className="py-1 font-display text-ink">{f.feature}</td>
                  <td className="py-1 text-ink">{f.value}</td>
                  <td className={`py-1 font-semibold font-display ${f.shap_value > 0 ? 'text-red-500' : 'text-emerald-500'}`}>
                    {f.shap_value > 0 ? '+' : ''}{f.shap_value}
                  </td>
                  <td className="py-1 text-ink-muted">{f.direction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-4 text-xs text-ink-muted">
        This is a probabilistic assessment from static analysis only. It is not a
        substitute for professional malware analysis and should not be the sole
        basis for a security decision.
      </p>
    </Card>
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
      <SectionLabel>analyze</SectionLabel>
      <h2 className="text-xl font-bold font-display mb-1 text-ink">Analyze Sample</h2>
      <p className="text-ink-muted text-sm mb-4">
        Static analysis only — the file is never executed.
      </p>
      <form onSubmit={handleSubmit} className="flex items-center gap-3">
        <input
          type="file"
          onChange={(e) => setFile(e.target.files[0])}
          className="text-sm text-ink file:mr-3 file:py-2 file:px-3 file:rounded-md file:border file:border-border file:bg-surface file:text-ink file:text-sm"
        />
        <button
          type="submit"
          disabled={!file || loading}
          className="bg-signal text-white px-4 py-2 rounded-md text-sm font-semibold font-display disabled:opacity-40 hover:opacity-90 transition"
        >
          {loading ? 'analyzing…' : 'analyze'}
        </button>
      </form>

      {error && (
        <div className="mt-4 text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-800 rounded-md p-3 text-sm font-display">
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
        <div>
          <SectionLabel>history</SectionLabel>
          <h2 className="text-xl font-bold font-display text-ink">Analysis History</h2>
        </div>
        <button onClick={load} className="text-sm text-ink-muted hover:text-signal font-display">
          refresh
        </button>
      </div>

      {loading ? (
        <p className="text-ink-muted text-sm font-display">loading…</p>
      ) : analyses.length === 0 ? (
        <Card className="p-6 text-sm text-ink-muted">
          No analyses yet. Head to <span className="text-signal font-display">Analyze Sample</span> to run one.
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left bg-surface border-b border-border font-display text-ink-muted">
                <th className="py-2 px-3 font-medium">File</th>
                <th className="py-2 px-3 font-medium">Classification</th>
                <th className="py-2 px-3 font-medium">Threat Level</th>
                <th className="py-2 px-3 font-medium">Confidence</th>
                <th className="py-2 px-3 font-medium">When</th>
              </tr>
            </thead>
            <tbody>
              {analyses.map((a) => (
                <tr
                  key={a.analysis_id}
                  onClick={() => setSelected(a)}
                  className="border-b border-border/60 cursor-pointer hover:bg-signal/5"
                >
                  <td className="py-2 px-3 font-display text-ink">{a.file_name}</td>
                  <td className="py-2 px-3"><ClassificationBadge classification={a.classification} /></td>
                  <td className="py-2 px-3"><TierBadge tier={a.threat_level} /></td>
                  <td className="py-2 px-3 text-ink">{(a.malicious_probability * 100).toFixed(2)}%</td>
                  <td className="py-2 px-3 text-ink-muted">
                    {a.created_at ? new Date(a.created_at).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <AnalysisResult result={selected} />
    </div>
  )
}

const TIER_COLORS = {
  LOW: '#10B981',
  MODERATE: '#EAB308',
  ELEVATED: '#F97316',
  HIGH: '#EF4444',
  CRITICAL: '#991B1B',
}
const TIER_ORDER = ['LOW', 'MODERATE', 'ELEVATED', 'HIGH', 'CRITICAL']
const AXIS_COLOR = '#94A3B8'

function ChartCard({ title, children }) {
  return (
    <Card className="p-4">
      <h3 className="text-sm font-semibold text-ink-muted font-display mb-3">{title}</h3>
      {children}
    </Card>
  )
}

function StatisticsTab() {
  const [stats, setStats] = useState(null)
  const [analyses, setAnalyses] = useState([])

  useEffect(() => {
    fetch('/api/statistics').then((r) => r.json()).then(setStats)
    fetch('/api/analyses?limit=50').then((r) => r.json()).then(setAnalyses)
  }, [])

  if (!stats) return <p className="text-ink-muted text-sm font-display">loading…</p>

  const classificationData = [
    { name: 'Malicious', value: stats.malicious },
    { name: 'Benign', value: stats.benign },
  ].filter((d) => d.value > 0)

  const tierData = TIER_ORDER
    .map((tier) => ({ tier, count: stats.threat_level_distribution?.[tier] || 0 }))
    .filter((d) => d.count > 0)

  const trendData = [...analyses]
    .reverse()
    .map((a, i) => ({
      index: i + 1,
      confidence: Math.round(a.malicious_probability * 10000) / 100,
    }))

  const familyCounts = {}
  analyses.forEach((a) => {
    if (a.predicted_family) familyCounts[a.predicted_family] = (familyCounts[a.predicted_family] || 0) + 1
  })
  const familyData = Object.entries(familyCounts)
    .map(([family, count]) => ({ family, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8)

  return (
    <div>
      <SectionLabel>dashboard</SectionLabel>
      <h2 className="text-xl font-bold font-display mb-4 text-ink">Overview</h2>
      <div className="grid grid-cols-3 gap-4 mb-6">
        <Card className="p-4">
          <div className="text-ink-muted text-sm">Total Analyses</div>
          <div className="text-2xl font-bold font-display text-ink">{stats.total_analyses}</div>
        </Card>
        <Card className="p-4">
          <div className="text-ink-muted text-sm">Malicious</div>
          <div className="text-2xl font-bold font-display text-red-500">{stats.malicious}</div>
        </Card>
        <Card className="p-4">
          <div className="text-ink-muted text-sm">Benign</div>
          <div className="text-2xl font-bold font-display text-emerald-500">{stats.benign}</div>
        </Card>
      </div>

      {stats.total_analyses === 0 ? (
        <Card className="p-6 text-sm text-ink-muted">
          No analyses yet. Charts will populate once you've run a few through <span className="text-signal font-display">Analyze Sample</span>.
        </Card>
      ) : (
        <div className="grid grid-cols-2 gap-4">
          <ChartCard title="Classification Split">
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={classificationData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={80} paddingAngle={3}>
                  {classificationData.map((d) => (
                    <Cell key={d.name} fill={d.name === 'Malicious' ? '#EF4444' : '#10B981'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--font-mono)' }} />
                <Legend wrapperStyle={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard title="Threat Level Distribution">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={tierData}>
                <CartesianGrid strokeDasharray="3 3" stroke={AXIS_COLOR} opacity={0.15} />
                <XAxis dataKey="tier" tick={{ fill: AXIS_COLOR, fontFamily: 'var(--font-mono)', fontSize: 11 }} />
                <YAxis allowDecimals={false} tick={{ fill: AXIS_COLOR, fontFamily: 'var(--font-mono)', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--font-mono)' }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {tierData.map((d) => (
                    <Cell key={d.tier} fill={TIER_COLORS[d.tier]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          {trendData.length > 1 && (
            <ChartCard title="Confidence Trend (recent analyses)">
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={AXIS_COLOR} opacity={0.15} />
                  <XAxis dataKey="index" tick={{ fill: AXIS_COLOR, fontFamily: 'var(--font-mono)', fontSize: 11 }} />
                  <YAxis unit="%" tick={{ fill: AXIS_COLOR, fontFamily: 'var(--font-mono)', fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--font-mono)' }} formatter={(v) => [`${v}%`, 'Confidence']} />
                  <Line type="monotone" dataKey="confidence" stroke="var(--signal)" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            </ChartCard>
          )}

          {familyData.length > 0 && (
            <ChartCard title="Predicted Family Breakdown">
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={familyData} layout="vertical" margin={{ left: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={AXIS_COLOR} opacity={0.15} />
                  <XAxis type="number" allowDecimals={false} tick={{ fill: AXIS_COLOR, fontFamily: 'var(--font-mono)', fontSize: 11 }} />
                  <YAxis dataKey="family" type="category" width={90} tick={{ fill: AXIS_COLOR, fontFamily: 'var(--font-mono)', fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--font-mono)' }} />
                  <Bar dataKey="count" fill="var(--signal)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>
          )}
        </div>
      )}
    </div>
  )
}

function ModelsTab() {
  const [models, setModels] = useState(null)

  useEffect(() => {
    fetch('/api/models').then((r) => r.json()).then(setModels)
  }, [])

  if (!models) return <p className="text-ink-muted text-sm font-display">loading…</p>

  return (
    <div>
      <SectionLabel>models</SectionLabel>
      <h2 className="text-xl font-bold font-display mb-4 text-ink">Loaded Models</h2>
      <Card className="p-4 space-y-2 text-sm">
        <div><span className="text-ink-muted">Malware Detector:</span> <span className="text-ink">{models.malware_detector}</span></div>
        <div><span className="text-ink-muted">Anomaly Detector:</span> <span className="text-ink">{models.anomaly_detector}</span></div>
        <div><span className="text-ink-muted">Family Classifier:</span> <span className="text-ink">{models.family_classifier || 'Not available'}</span></div>
        <div className="pt-2 text-xs text-ink-muted border-t border-border mt-2 font-display">
          {models.training_scope}
        </div>
      </Card>
    </div>
  )
}

const TABS = [
  { id: 'dashboard', label: 'Dashboard', component: StatisticsTab },
  { id: 'analyze', label: 'Analyze Sample', component: AnalyzeTab },
  { id: 'history', label: 'History', component: HistoryTab },
  { id: 'graph', label: 'Threat Graph', component: GraphTab },
  { id: 'models', label: 'Models', component: ModelsTab },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const ActiveComponent = TABS.find((t) => t.id === activeTab).component

  return (
    <div className="min-h-screen relative">
      <ParticleBackground />

      <header className="relative z-10 bg-surface/80 backdrop-blur border-b border-border px-6 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold font-display text-ink tracking-tight">ThreatLens</h1>
          <p className="text-ink-muted text-xs font-display">
            static_analysis_only :: never_executes_files
          </p>
        </div>
        <ThemeToggle />
      </header>

      <nav className="relative z-10 bg-surface/60 backdrop-blur border-b border-border px-6 flex gap-1">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-3 text-sm font-medium font-display border-b-2 transition ${
              activeTab === tab.id
                ? 'border-signal text-signal'
                : 'border-transparent text-ink-muted hover:text-ink'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="relative z-10 max-w-4xl mx-auto px-6 py-8">
        <ActiveComponent />
      </main>
    </div>
  )
}