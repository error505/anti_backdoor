/** Decorative, fixed background layers: drifting glows, a perspective grid floor, scanlines. */
export function SciFiBackdrop() {
  return (
    <div className="backdrop" aria-hidden="true">
      <div className="backdrop-glow backdrop-glow-a" />
      <div className="backdrop-glow backdrop-glow-b" />
      <div className="backdrop-grid" />
      <div className="backdrop-floor" />
      <div className="backdrop-scanlines" />
      <div className="backdrop-sweep" />
      <div className="backdrop-vignette" />
    </div>
  );
}
