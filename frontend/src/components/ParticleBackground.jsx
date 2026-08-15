import { useEffect, useRef } from 'react'

// Ambient network-graph animation: nodes drift slowly and connect to nearby
// neighbors with fading lines, occasionally pulsing brighter -- a visual
// echo of the "threat intelligence graph" concept from the project's own
// blueprint (samples as nodes, shared characteristics as edges), not pure
// decoration. Reads the --signal CSS custom property at draw time so it
// automatically follows the light/dark theme.
export default function ParticleBackground() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    let width, height, nodes, animationId
    const NODE_COUNT = 55
    const LINK_DISTANCE = 130

    function resize() {
      width = canvas.width = window.innerWidth
      height = canvas.height = window.innerHeight
    }

    function makeNodes() {
      nodes = Array.from({ length: NODE_COUNT }, () => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.25,
        vy: (Math.random() - 0.5) * 0.25,
        pulse: Math.random() * Math.PI * 2,
      }))
    }

    function getSignalColor() {
      const style = getComputedStyle(document.documentElement)
      return style.getPropertyValue('--signal').trim() || '#2F6FED'
    }

    function hexToRgb(hex) {
      const m = hex.replace('#', '')
      const bigint = parseInt(m, 16)
      return [(bigint >> 16) & 255, (bigint >> 8) & 255, bigint & 255]
    }

    function draw() {
      ctx.clearRect(0, 0, width, height)
      const [r, g, b] = hexToRgb(getSignalColor())

      for (const node of nodes) {
        node.x += node.vx
        node.y += node.vy
        if (node.x < 0 || node.x > width) node.vx *= -1
        if (node.y < 0 || node.y > height) node.vy *= -1
        node.pulse += 0.01
      }

      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b2 = nodes[j]
          const dx = a.x - b2.x, dy = a.y - b2.y
          const dist = Math.sqrt(dx * dx + dy * dy)
          if (dist < LINK_DISTANCE) {
            const opacity = (1 - dist / LINK_DISTANCE) * 0.15
            ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${opacity})`
            ctx.lineWidth = 1
            ctx.beginPath()
            ctx.moveTo(a.x, a.y)
            ctx.lineTo(b2.x, b2.y)
            ctx.stroke()
          }
        }
      }

      for (const node of nodes) {
        const pulseOpacity = 0.35 + Math.sin(node.pulse) * 0.2
        ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${pulseOpacity})`
        ctx.beginPath()
        ctx.arc(node.x, node.y, 1.6, 0, Math.PI * 2)
        ctx.fill()
      }

      if (!prefersReducedMotion) {
        animationId = requestAnimationFrame(draw)
      }
    }

    resize()
    makeNodes()
    draw()

    window.addEventListener('resize', resize)
    return () => {
      window.removeEventListener('resize', resize)
      if (animationId) cancelAnimationFrame(animationId)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 w-full h-full pointer-events-none"
      style={{ zIndex: 0 }}
      aria-hidden="true"
    />
  )
}