/**
 * SECURITY (2.1.0): preloader del tema (light/dark).
 * Spostato da <script> inline a file esterno per poter applicare una
 * Content-Security-Policy senza 'unsafe-inline' su script-src.
 * Deve essere caricato in modo sincrono nel <head> (prima del paint) per
 * evitare il "flash" di tema errato.
 */
(function () {
  const savedTheme = localStorage.getItem('pki-theme');
  if (savedTheme) {
    document.documentElement.setAttribute('data-theme', savedTheme);
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();
