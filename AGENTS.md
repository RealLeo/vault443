# Vault 443 project guidance

For work on `website/`, read and apply the project-local skills in
`.agents/skills/frontend-design`, `gsap-core`, `gsap-timeline`,
`gsap-scrolltrigger` and `gsap-performance` before changing design or motion.
Their upstream versions and file hashes are recorded in
`.agents/skills/sources.json`; retain their separate licenses.

The landing page is a static GitHub Pages site, built with
`python3 website/build.py --offline` for local work. Its English and Russian
content must stay equivalent. Generated artwork and prompts live in
`design/landing/`; production assets live in `website/assets/`.
Keep downloads functional without JavaScript, honor reduced motion. Sound is enabled by default at the user’s request; unlock
Web Audio on the first trusted click/key gesture, respect browser autoplay
restrictions, and keep immediate mute available. Browser QA uses the available CUA
browser. Website changes do not require rebuilding or republishing VPN packages.
These web-specific instructions do not apply to the Qt interface or Go service.
