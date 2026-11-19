export default function Background() {
  return (
    <div className="backdrop" aria-hidden="true">
      <div className="backdrop__wash" />
      <div className="backdrop__orb backdrop__orb--a" />
      <div className="backdrop__orb backdrop__orb--b" />
      <div className="backdrop__orb backdrop__orb--c" />
      <div className="backdrop__grid" />
    </div>
  );
}
