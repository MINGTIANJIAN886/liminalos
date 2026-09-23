const observer = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) entry.target.classList.add("in");
  });
}, { threshold: .12 });

document.querySelectorAll(".reveal").forEach((element) => observer.observe(element));

const cognitionScroll = document.querySelector("[data-cognition-scroll]");
if (cognitionScroll) {
  const story = cognitionScroll.querySelector("[data-cognition-story]");
  const stage = story.querySelector(".cognition-scroll-stage");
  const progress = story.querySelector(".cognition-scroll-progress");
  const panels = [...story.querySelectorAll("[data-cognition-panel]")];
  const labels = [...story.querySelectorAll("[data-cognition-label]")];
  const mobile = window.matchMedia("(max-width: 720px)");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let currentIndex = -1;
  let frame = 0;

  const setActive = (index) => {
    if (index === currentIndex) return;
    currentIndex = index;
    labels.forEach((label, i) => {
      label.classList.toggle("is-active", i === index);
      if (i === index) label.setAttribute("aria-current", "step");
      else label.removeAttribute("aria-current");
    });
    panels.forEach((panel, i) => {
      panel.classList.toggle("is-active", i === index);
      panel.setAttribute("aria-hidden", String(!mobile.matches && i !== index));
      panel.inert = !mobile.matches && i !== index;
    });
  };

  const metrics = () => {
    const top = window.scrollY + story.getBoundingClientRect().top - parseFloat(getComputedStyle(stage).top);
    const travel = Math.max(1, story.offsetHeight - stage.offsetHeight);
    return { top, travel, step: travel / panels.length };
  };

  const sync = () => {
    frame = 0;
    if (mobile.matches) {
      let index = 0;
      panels.forEach((panel, i) => {
        if (panel.getBoundingClientRect().top <= window.innerHeight * .42) index = i;
      });
      setActive(index);
      return;
    }
    const { top, travel } = metrics();
    const value = Math.min(1, Math.max(0, (window.scrollY - top) / travel));
    progress.style.setProperty("--story-progress", `${(value * 100).toFixed(2)}%`);
    setActive(Math.min(panels.length - 1, Math.floor(value * panels.length)));
  };

  const scheduleSync = () => {
    if (!frame) frame = requestAnimationFrame(sync);
  };

  const goTo = (index, updateHash = true) => {
    const behavior = reduceMotion.matches ? "instant" : "smooth";
    if (mobile.matches) panels[index].scrollIntoView({ behavior, block: "start" });
    else {
      const { top, step } = metrics();
      window.scrollTo({ top: top + index * step + 2, behavior });
    }
    if (updateHash) history.replaceState(null, "", `#${panels[index].id}`);
  };

  labels.forEach((label, index) => {
    label.addEventListener("click", (event) => {
      event.preventDefault();
      goTo(index);
    });
    label.addEventListener("keydown", (event) => {
      const next = event.key === "ArrowRight" ? (index + 1) % labels.length
        : event.key === "ArrowLeft" ? (index - 1 + labels.length) % labels.length
        : event.key === "Home" ? 0 : event.key === "End" ? labels.length - 1 : null;
      if (next === null) return;
      event.preventDefault();
      labels[next].focus();
      goTo(next);
    });
  });

  const updateMode = () => {
    cognitionScroll.classList.toggle("is-interactive", !mobile.matches);
    currentIndex = -1;
    sync();
  };
  window.addEventListener("scroll", scheduleSync, { passive: true });
  window.addEventListener("resize", scheduleSync);
  mobile.addEventListener("change", updateMode);
  updateMode();
  const initialIndex = panels.findIndex((panel) => `#${panel.id}` === location.hash);
  if (initialIndex > 0) requestAnimationFrame(() => goTo(initialIndex, false));
}

const mechanismVideos = document.querySelectorAll(".mechanism-media video");
if (mechanismVideos.length) {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reduceMotion) {
    const videoObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) entry.target.play().catch(() => {});
        else entry.target.pause();
      });
    }, { threshold: .25, rootMargin: "100px 0px" });
    mechanismVideos.forEach((video) => videoObserver.observe(video));
  }
}

document.querySelectorAll("a[href^='#']").forEach((link) => {
  link.addEventListener("click", () => {
    const target = document.querySelector(link.getAttribute("href"));
    if (target) target.setAttribute("tabindex", "-1");
  });
});

/* Research system map: link the light step navigation to the imported map. */
const architectureMap = document.querySelector("#architecture .system-map-visual");
const architectureNavItems = [...document.querySelectorAll("#architecture .workflow-timeline li[data-map-target]")];

if (architectureMap && architectureNavItems.length) {
  const focusClasses = [
    "is-focus-resources",
    "is-focus-task",
    "is-focus-orchestration",
    "is-focus-adjustment",
    "is-focus-feedback"
  ];

  const setArchitectureFocus = (target, activeItem) => {
    architectureMap.classList.remove(...focusClasses);
    architectureMap.classList.add(`is-focus-${target}`);
    architectureNavItems.forEach((item) => item.classList.toggle("is-active", item === activeItem));
  };

  const resetArchitectureFocus = () => {
    architectureMap.classList.remove(...focusClasses);
    architectureNavItems.forEach((item, index) => item.classList.toggle("is-active", index === 0));
  };

  architectureNavItems.forEach((item) => {
    const target = item.dataset.mapTarget;
    ["mouseenter", "focus", "click"].forEach((eventName) => {
      item.addEventListener(eventName, () => setArchitectureFocus(target, item));
    });
  });

  document.querySelector("#architecture .workflow-timeline")?.addEventListener("mouseleave", resetArchitectureFocus);
  resetArchitectureFocus();
}
