import { useState, useEffect, useRef, useMemo } from 'react'
import ForceGraph2D from 'react-force-graph-2d'

const TIER_COLORS = {
  LOW: '#10B981',
  MODERATE: '#EAB308',
  ELEVATED: '#F97316',
  HIGH: '#EF4444',
  CRITICAL: '#991B1B',
}
const FAMILY_COLOR = '#2F6FED'

export default function GraphTab() {
  const [graphData, setGraphData] = useState(null)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const containerRef = useRef(null)
  const [dims, setDims] = useState({ width: 800, height: 500 })

  useEffect(() => {
    fetch('/api/graph')
      .then((r) => {
        if (!r.ok) return r.json().then((b) => { throw new Error(b.detail || 'Failed to load graph') })
        return r.json()
      })
      .then((data) => {
        // react-force-graph mutates node objects in place to track x/y
        // positions -- give it its own copies, not the raw fetched data.
        setGraphData({
          nodes: data.nodes.map((n) => ({ ...n })),
          links: data.links.map((l) => ({ ...l })),
        })
      })
      .catch((e) => setError(e.message))
  }, [])

  useEffect(() => {
    if (!containerRef.current) return
    const resize = () => {
      setDims({
        width: containerRef.current.offsetWidth,
        height: Math.max(500, window.innerHeight - 260),
      })
    }
    resize()
    window.addEventListener('resize', resize)
    return () => window.removeEventListener('resize', resize)
  }, [])

  const nodeColor = useMemo(() => (node) => {
    if (node.kind === 'family') return FAMILY_COLOR
    return TIER_COLORS[node.threat_level] || '#94A3B8'
  }, [])

  if (error) {
    return (
      <div>
        <div className="font-display text-signal text-xs tracking-wider mb-2">// threat_graph</div>
        <h2 className="text-xl font-bold font-display mb-4 text-ink">Threat Intelligence Graph</h2>
        <div className="bg-surface/90 backdrop-blur border border-border rounded-lg p-6 text-sm text-ink-muted">
          {error} — run <span className="font-display text-signal">python ml-training/src/build_threat_graph.py</span> first.
        </div>
      </div>
    )
  }

  if (!graphData) {
    return <p className="text-ink-muted text-sm font-display">loading graph…</p>
  }

  return (
    <div>
      <div className="font-display text-signal text-xs tracking-wider mb-2">// threat_graph</div>
      <h2 className="text-xl font-bold font-display mb-1 text-ink">Threat Intelligence Graph</h2>
      <p className="text-ink-muted text-sm mb-4">
        {graphData.nodes.length} nodes, {graphData.links.length} edges. Blue = malware family. Colored = sample, by threat level. Drag to explore, scroll to zoom, click a node for details.
      </p>

      <div ref={containerRef} className="bg-surface/90 backdrop-blur border border-border rounded-lg overflow-hidden">
        <ForceGraph2D
          graphData={graphData}
          width={dims.width}
          height={dims.height}
          nodeColor={nodeColor}
          nodeRelSize={4}
          nodeVal={(n) => (n.kind === 'family' ? 8 : 2)}
          linkColor={() => 'rgba(148, 163, 184, 0.25)'}
          linkWidth={(l) => (l.relation === 'belongs_to' ? 1.5 : 0.5)}
          onNodeClick={(node) => setSelected(node)}
          nodeLabel={(node) => (node.kind === 'family' ? node.name : `${node.id} (${node.threat_level})`)}
          d3VelocityDecay={0.4}
          warmupTicks={80}
          cooldownTicks={50}
          cooldownTime={4000}
        />
      </div>

      {selected && (
        <div className="mt-4 bg-surface/90 backdrop-blur border border-border rounded-lg p-4 text-sm">
          <div className="font-display text-signal text-xs mb-2">// selected_node</div>
          {selected.kind === 'family' ? (
            <div className="text-ink">
              <span className="text-ink-muted">Family:</span> <span className="font-display font-semibold">{selected.name}</span>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-2 text-ink">
              <div><span className="text-ink-muted">Sample:</span> <span className="font-display">{selected.id}</span></div>
              <div><span className="text-ink-muted">Classification:</span> <span className="font-display">{selected.classification}</span></div>
              <div><span className="text-ink-muted">Threat Level:</span> <span className="font-display">{selected.threat_level}</span></div>
              <div><span className="text-ink-muted">Confidence:</span> <span className="font-display">{selected.malicious_probability != null ? `${(selected.malicious_probability * 100).toFixed(2)}%` : '—'}</span></div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}