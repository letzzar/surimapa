/* Aplica el tema guardado ANTES de pintar (script externo en <head>: la CSP no permite scripts en línea). */
"use strict";
(() => {
  try {
    const t = localStorage.getItem("surimapa-theme");
    if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  } catch { /* sin almacenamiento: tema por defecto (oscuro) */ }
})();
