/* Vault 443 — progressive enhancement. Downloads and core content are static HTML. */
(() => {
  "use strict";
  const allowsMotion = (preference, reduced) => preference !== "off" && !reduced;
  const wrapIndex = (index, length) => ((index % length) + length) % length;
  function createDoorController({ enabled, open, animate, remembered, remember }) {
    let initialized = false;
    let timeline = null;
    const finish = () => { if (timeline) timeline.kill(); timeline = null; open(); };
    const replay = () => {
      finish();
      if (!enabled()) return;
      timeline = animate(() => { timeline = null; open(); });
    };
    const init = () => {
      if (initialized) return;
      initialized = true;
      let played = false;
      try { played = remembered(); } catch {}
      if (enabled() && !played) { try { remember(); } catch {} replay(); }
      else finish();
    };
    return { init, replay, finish };
  }
  if (typeof document === "undefined") {
    if (typeof module !== "undefined") module.exports = { allowsMotion, wrapIndex, createDoorController };
    return;
  }
  const dataElement = document.getElementById("page-data");
  if (!dataElement) return;
  const data = JSON.parse(dataElement.textContent);
  const root = document.documentElement;
  const gsap = window.gsap;
  const scrollTrigger = window.ScrollTrigger;
  const media = window.matchMedia("(prefers-reduced-motion: reduce)");
  const motionButton = document.querySelector(".motion-button");
  const soundButton = document.querySelector(".sound-button");
  const doorReplay = document.querySelector(".door-replay");
  const playButton = document.getElementById("demo-play");
  const status = document.getElementById("demo-status");
  const readPreference = () => { try { return localStorage.getItem("vault443-motion"); } catch { return null; } };
  let preference = readPreference();
  let motionContext = null;
  let demoTimeline = null;
  let currentScenario = 0;
  let audioContext = null;
  let soundEnabled = false;
  const oscillators = new Set();
  let galleryIndex = 0;
  let galleryTimeline = null;
  let returnFocus = null;

  document.querySelectorAll("[data-js-only]").forEach(element => { element.hidden = false; });
  root.dataset.enhanced = "true";
  if (gsap && scrollTrigger) gsap.registerPlugin(scrollTrigger);

  const canAnimate = () => Boolean(gsap) && allowsMotion(preference, media.matches);
  function tone(frequency = 580, duration = 0.055) {
    if (!soundEnabled || !audioContext || audioContext.state !== "running" || document.hidden) return;
    const oscillator = audioContext.createOscillator();
    const gain = audioContext.createGain();
    const start = audioContext.currentTime;
    oscillator.type = "square";
    oscillator.frequency.setValueAtTime(frequency, start);
    oscillator.frequency.exponentialRampToValueAtTime(frequency * 0.65, start + duration);
    gain.gain.setValueAtTime(0.0001, start);
    gain.gain.exponentialRampToValueAtTime(0.015, start + 0.004);
    gain.gain.exponentialRampToValueAtTime(0.0001, start + duration);
    oscillator.connect(gain);
    gain.connect(audioContext.destination);
    oscillators.add(oscillator);
    oscillator.onended = () => { oscillators.delete(oscillator); oscillator.disconnect(); gain.disconnect(); };
    oscillator.start(start);
    oscillator.stop(start + duration + 0.01);
  }
  function silence() {
    for (const oscillator of oscillators) { try { oscillator.stop(); } catch {} }
    oscillators.clear();
  }
  soundButton.addEventListener("click", async () => {
    if (soundEnabled) {
      soundEnabled = false;
      silence();
      if (audioContext) await audioContext.suspend();
    } else {
      const Context = window.AudioContext || window.webkitAudioContext;
      if (!Context) { soundButton.disabled = true; return; }
      try {
        if (!audioContext) audioContext = new Context();
        await audioContext.resume();
        soundEnabled = true;
        tone(790, 0.065);
      } catch { soundEnabled = false; }
    }
    soundButton.setAttribute("aria-pressed", String(soundEnabled));
    soundButton.title = soundEnabled ? data.controls.soundOn : data.controls.soundOff;
  });
  document.querySelectorAll("button, .metal-button, .gallery-choice, .scenario-choice").forEach(element => {
    element.addEventListener("pointerdown", () => tone(490, 0.035));
  });

  const assembly = document.querySelector(".vault-assembly");
  const shutters = document.querySelector(".vault-shutters");
  const leftShutter = document.querySelector(".shutter-left");
  const rightShutter = document.querySelector(".shutter-right");
  const cams = [...document.querySelectorAll(".cam-sprite")];
  const lamps = [...document.querySelectorAll(".lamp-shade")];
  const glow = document.querySelector(".vault-glow");
  function openDoor() {
    assembly.dataset.doorState = "open";
    shutters.style.visibility = "hidden";
    if (gsap) {
      gsap.set(leftShutter, { x: 0, xPercent: -51 });
      gsap.set(rightShutter, { x: 0, xPercent: 51 });
      gsap.set(cams, { rotation: 0 });
      gsap.set([...lamps, glow], { opacity: 0 });
    } else {
      leftShutter.style.transform = "translateX(-51%)";
      rightShutter.style.transform = "translateX(51%)";
      cams.forEach(cam => { cam.style.transform = ""; });
      [...lamps, glow].forEach(lamp => { lamp.style.opacity = "0"; });
    }
    doorReplay.disabled = !canAnimate();
  }
  const door = createDoorController({
    enabled: canAnimate,
    open: openDoor,
    remembered: () => sessionStorage.getItem("vault443-door-booted") === "1",
    remember: () => sessionStorage.setItem("vault443-door-booted", "1"),
    animate: complete => {
      assembly.dataset.doorState = "opening";
      doorReplay.disabled = true;
      const timeline = gsap.timeline({ defaults: { ease: "power2.inOut" }, onComplete: complete });
      timeline.addLabel("unlock", 0).addLabel("retract", 0.12).addLabel("power", 0.3);
      timeline.set(shutters, { visibility: "visible" }, "unlock")
        .set([leftShutter, rightShutter], { x: 0, xPercent: 0 }, "unlock")
        .set(cams, { rotation: 18 }, "unlock")
        .set(lamps, { opacity: 0.9 }, "unlock")
        .set(glow, { opacity: 0 }, "unlock")
        .call(() => tone(210, 0.05), [], "unlock")
        .to(cams, { rotation: 0, duration: 0.18, ease: "power1.out" }, "unlock")
        .to(leftShutter, { xPercent: -51, duration: 0.6 }, "retract")
        .to(rightShutter, { xPercent: 51, duration: 0.6 }, "retract")
        .to(lamps, { opacity: 0, duration: 0.22, stagger: { amount: 0.38 } }, "power")
        .to(glow, { opacity: 0.2, duration: 0.15 }, 0.5)
        .to(glow, { opacity: 0, duration: 0.25 }, 0.65)
        .call(() => tone(770, 0.04), [], 0.8);
      return timeline;
    }
  });
  doorReplay.addEventListener("click", () => door.replay());

  const wires = [...document.querySelectorAll(".route-wire")];
  const wireLengths = new Map(wires.map(wire => [wire, wire.getTotalLength()]));
  function showRoutes(names) {
    for (const wire of wires) {
      const active = names.includes(wire.dataset.route);
      wire.style.stroke = active ? "#a8c871" : "#49513b";
      wire.style.opacity = active ? "1" : "0.4";
      wire.style.strokeDasharray = "none";
      wire.style.strokeDashoffset = "0";
    }
  }
  function cancelDemo() {
    if (demoTimeline) { demoTimeline.kill(); demoTimeline = null; }
    playButton.disabled = false;
    playButton.classList.remove("is-running");
  }
  function setScenario(index) {
    cancelDemo();
    currentScenario = index;
    const scenario = data.demo.scenarios[index];
    document.getElementById("scenario-description").textContent = scenario.description;
    document.querySelector(".route-diagram").setAttribute("aria-label", scenario.description);
    status.textContent = data.demo.ready;
    playButton.querySelector(".power-caption").textContent = data.demo.play;
    showRoutes(scenario.active);
  }
  document.querySelectorAll('input[name="scenario"]').forEach(input => {
    input.addEventListener("change", () => setScenario(Number(input.value)));
  });
  function finishDemo(scenario) {
    showRoutes(scenario.active);
    status.textContent = data.demo.complete;
    playButton.disabled = false;
    playButton.classList.remove("is-running");
    playButton.querySelector(".power-caption").textContent = data.demo.replay;
    tone(940, 0.08);
  }
  playButton.addEventListener("click", () => {
    cancelDemo();
    const scenario = data.demo.scenarios[currentScenario];
    if (!canAnimate()) { finishDemo(scenario); return; }
    playButton.disabled = true;
    playButton.classList.add("is-running");
    playButton.querySelector(".power-caption").textContent = data.demo.playing;
    for (const wire of wires) {
      gsap.set(wire, { stroke: "#49513b", opacity: 0.4, strokeDasharray: wireLengths.get(wire), strokeDashoffset: 0 });
    }
    demoTimeline = gsap.timeline({ defaults: { duration: 0.6, ease: "power1.inOut" }, onComplete: () => finishDemo(scenario) });
    scenario.steps.forEach((step, index) => {
      demoTimeline.addLabel("stage" + index);
      demoTimeline.call(() => { status.textContent = step; tone(520 + index * 110, 0.035); }, [], "stage" + index);
      const route = scenario.active[index];
      const wire = wires.find(item => item.dataset.route === route);
      if (wire) demoTimeline.fromTo(wire, { stroke: "#a8c871", opacity: 1, strokeDashoffset: wireLengths.get(wire) }, { strokeDashoffset: 0, immediateRender: false }, "stage" + index);
      else demoTimeline.to({}, { duration: 0.4 }, "stage" + index);
    });
  });

  function startMotion() {
    if (motionContext) { motionContext.revert(); motionContext = null; }
    door.finish();
    const allowed = canAnimate();
    root.dataset.motion = allowed ? "on" : "off";
    motionButton.setAttribute("aria-pressed", String(allowed));
    motionButton.disabled = media.matches || !gsap;
    motionButton.title = media.matches ? data.controls.motionSystem : allowed ? data.controls.motionOn : data.controls.motionOff;
    if (!allowed) {
      if (demoTimeline && demoTimeline.progress() < 1) { cancelDemo(); finishDemo(data.demo.scenarios[currentScenario]); }
      if (galleryTimeline) { galleryTimeline.progress(1); galleryTimeline.kill(); galleryTimeline = null; }
      door.init();
      return;
    }
    motionContext = gsap.matchMedia();
    motionContext.add("(prefers-reduced-motion: no-preference)", () => {
      if (scrollTrigger) {
        document.querySelectorAll(".routing-console, .gallery-preview, .package-console").forEach(panel => {
          const fasteners = panel.querySelectorAll(".panel-fastener");
          if (!fasteners.length) {
            ["left", "right"].forEach(side => {
              const fastener = document.createElement("span");
              fastener.className = "panel-fastener fastener-" + side;
              fastener.setAttribute("aria-hidden", "true");
              panel.appendChild(fastener);
            });
          }
          gsap.fromTo(panel.querySelectorAll(".panel-fastener"), { rotation: -18 }, { rotation: 0, duration: 0.35, ease: "power1.out", clearProps: "transform", scrollTrigger: { trigger: panel, start: "top 88%", once: true } });
        });
      }
    }, document.body);
    door.init();
  }
  motionButton.addEventListener("click", () => {
    preference = root.dataset.motion === "on" ? "off" : "on";
    try { localStorage.setItem("vault443-motion", preference); } catch {}
    startMotion();
  });
  media.addEventListener("change", startMotion);
  startMotion();
  setScenario(0);

  const galleryImage = document.getElementById("gallery-image");
  const galleryCaption = document.getElementById("gallery-caption");
  const galleryChoices = [...document.querySelectorAll(".gallery-choice")];
  function selectScreenshot(index, animate = true) {
    const next = wrapIndex(index, data.gallery.length);
    if (galleryTimeline) { galleryTimeline.kill(); galleryTimeline = null; }
    const apply = () => {
      galleryIndex = next;
      const item = data.gallery[next];
      galleryImage.src = item.src;
      galleryImage.alt = item.alt;
      galleryCaption.textContent = item.caption;
      galleryChoices.forEach((choice, current) => {
        choice.classList.toggle("is-active", current === next);
        if (current === next) choice.setAttribute("aria-current", "true"); else choice.removeAttribute("aria-current");
      });
      if (scrollTrigger) scrollTrigger.refresh();
    };
    if (animate && canAnimate()) {
      galleryTimeline = gsap.timeline({ defaults: { duration: 0.09, ease: "power1.inOut" } });
      galleryTimeline.fromTo(".gallery-shutter", { scaleY: 0 }, { scaleY: 1 }).call(apply).to(".gallery-shutter", { scaleY: 0 });
    } else { apply(); if (gsap) gsap.set(".gallery-shutter", { scaleY: 0 }); }
  }
  galleryChoices.forEach((choice, index) => {
    choice.addEventListener("click", event => { event.preventDefault(); selectScreenshot(index); });
    choice.addEventListener("keydown", event => {
      if (!["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const target = event.key === "Home" ? 0 : event.key === "End" ? data.gallery.length - 1 : wrapIndex(index + (["ArrowUp", "ArrowLeft"].includes(event.key) ? -1 : 1), data.gallery.length);
      galleryChoices[target].focus(); selectScreenshot(target);
    });
  });
  document.getElementById("gallery-prev").addEventListener("click", () => selectScreenshot(galleryIndex - 1));
  document.getElementById("gallery-next").addEventListener("click", () => selectScreenshot(galleryIndex + 1));
  const dialog = document.getElementById("screenshot-dialog");
  function openScreenshot(item, trigger) {
    if (typeof dialog.showModal !== "function") { window.location.href = item.src; return; }
    door.finish();
    returnFocus = trigger;
    const image = document.getElementById("dialog-image");
    image.src = item.src; image.alt = item.alt;
    document.getElementById("dialog-caption").textContent = item.caption;
    dialog.showModal();
    dialog.querySelector("button").focus();
  }
  document.getElementById("gallery-enlarge").addEventListener("click", event => openScreenshot(data.gallery[galleryIndex], event.currentTarget));
  document.querySelector("[data-hero-preview]").addEventListener("click", event => {
    event.preventDefault();
    openScreenshot(data.hero, event.currentTarget);
  });
  document.querySelectorAll("[data-feature-screen]").forEach(link => {
    link.addEventListener("click", () => {
      const index = data.gallery.findIndex(item => item.file === link.dataset.featureScreen);
      if (index >= 0) selectScreenshot(index, false);
    });
  });
  dialog.querySelector(".dialog-close").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", event => { if (event.target === dialog) dialog.close(); });
  dialog.addEventListener("close", () => { if (returnFocus) returnFocus.focus(); });

  document.querySelectorAll("[data-copy]").forEach(button => {
    button.addEventListener("click", async () => {
      const code = document.getElementById(button.dataset.copy);
      try { await navigator.clipboard.writeText(code.textContent); button.textContent = data.downloads.copied; }
      catch {
        const range = document.createRange(); range.selectNodeContents(code);
        const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
        button.textContent = data.downloads.copyFailed;
      }
      window.setTimeout(() => { button.textContent = data.downloads.copy; }, 2200);
    });
  });
  document.querySelectorAll(".language-link").forEach(link => {
    link.addEventListener("click", () => { link.hash = window.location.hash; });
  });
  const demoObserver = new IntersectionObserver(entries => {
    if (!demoTimeline || !demoTimeline.isActive() && !demoTimeline.paused()) return;
    const visible = entries[0].isIntersecting && !document.hidden;
    if (visible) demoTimeline.resume(); else demoTimeline.pause();
  }, { threshold: 0.05 });
  demoObserver.observe(document.getElementById("routes"));
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      silence();
      door.finish();
      if (gsap) gsap.ticker.sleep();
    } else if (gsap) gsap.ticker.wake();
  });
  galleryImage.addEventListener("load", () => { if (scrollTrigger) scrollTrigger.refresh(); });
  if (document.fonts) document.fonts.ready.then(() => { if (scrollTrigger) scrollTrigger.refresh(); });
  window.addEventListener("pagehide", event => {
    silence();
    door.finish();
    if (event.persisted) return;
    demoObserver.disconnect();
    if (motionContext) motionContext.revert();
    cancelDemo();
    if (galleryTimeline) galleryTimeline.kill();
  });
  window.addEventListener("pageshow", event => { if (event.persisted) { if (gsap) gsap.ticker.wake(); startMotion(); } });
})();
