// Apply the analyst's saved theme before the first paint. Dark is the default; the choice stays in this browser.
(function () {
  try {
    if (window.localStorage.getItem("romulus-theme") === "light") {
      document.documentElement.setAttribute("data-theme", "light");
    }
  } catch (error) {
    // storage unavailable: keep the default theme
  }
})();
