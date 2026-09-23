(() => {
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  document.querySelectorAll(".team-carousel").forEach((carousel) => {
    const track = carousel.querySelector(".team-grid");
    const prev = carousel.querySelector(".team-nav--prev");
    const next = carousel.querySelector(".team-nav--next");
    const dots = carousel.querySelector(".team-dots");
    if (!track || !prev || !next || !dots) return;
    const AUTO_DELAY = 3600;
    let autoTimer = 0;
    let hovering = false;
    const pageCount = () => Math.max(1, Math.round(track.scrollWidth / track.clientWidth));
    const canScroll = () => track.scrollWidth > track.clientWidth + 4;
    const syncState = () => {
      const total = pageCount();
      const index = Math.min(total - 1, Math.round(track.scrollLeft / track.clientWidth));
      [...dots.children].forEach((dot, i) => dot.classList.toggle("is-active", i === index));
      prev.disabled = track.scrollLeft <= 2;
      next.disabled = track.scrollLeft >= track.scrollWidth - track.clientWidth - 2;
    };
    const stopAuto = () => { if (autoTimer) window.clearInterval(autoTimer); autoTimer = 0; };
    const nextPage = () => {
      const total = pageCount();
      const index = Math.round(track.scrollLeft / track.clientWidth);
      track.scrollTo({ left: (index + 1 >= total ? 0 : index + 1) * track.clientWidth, behavior: "smooth" });
    };
    const restartAuto = () => {
      stopAuto();
      if (reducedMotion) return;
      autoTimer = window.setInterval(() => {
        if (!hovering && document.visibilityState === "visible" && canScroll()) nextPage();
      }, AUTO_DELAY);
    };
    const buildDots = () => {
      const total = pageCount();
      dots.replaceChildren();
      for (let i = 0; i < total; i += 1) {
        const dot = document.createElement("button");
        dot.type = "button";
        dot.setAttribute("aria-label", `第 ${i + 1} 组`);
        dot.addEventListener("click", () => { track.scrollTo({ left: i * track.clientWidth, behavior: "smooth" }); restartAuto(); });
        dots.append(dot);
      }
      syncState();
    };
    prev.addEventListener("click", () => { track.scrollBy({ left: -track.clientWidth, behavior: "smooth" }); restartAuto(); });
    next.addEventListener("click", () => { track.scrollBy({ left: track.clientWidth, behavior: "smooth" }); restartAuto(); });
    carousel.addEventListener("mouseenter", () => { hovering = true; });
    carousel.addEventListener("mouseleave", () => { hovering = false; });
    track.addEventListener("scroll", () => requestAnimationFrame(syncState), { passive: true });
    window.addEventListener("resize", () => { buildDots(); restartAuto(); });
    window.addEventListener("load", buildDots);
    buildDots();
    restartAuto();
  });
})();