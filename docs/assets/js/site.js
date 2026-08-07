/* ============================================================================
   Halation site behaviour

   Everything here is decoration over content that already reads correctly
   without it. Nothing is hidden until this file has run and confirmed it can
   put it back: the reveal styles are scoped to a class this script adds, so a
   browser with scripting off, or one where this file fails to load, gets the
   whole page rather than an empty one.
   ========================================================================= */

(function () {
  'use strict';

  var root = document.documentElement;
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---- Navigation ------------------------------------------------------ */

  var nav = document.querySelector('.nav');
  var toggle = document.querySelector('.nav__toggle');
  var links = document.querySelector('.nav__links');

  if (nav) {
    var onScroll = function () {
      nav.classList.toggle('is-scrolled', window.scrollY > 12);
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  if (toggle && links) {
    toggle.addEventListener('click', function () {
      var open = links.classList.toggle('is-open');
      toggle.setAttribute('aria-expanded', String(open));
    });

    links.addEventListener('click', function (event) {
      if (event.target.tagName === 'A') {
        links.classList.remove('is-open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  /* ---- Coming into view -------------------------------------------------
     Driven by getBoundingClientRect on scroll rather than by an
     IntersectionObserver. The observer is the tidier API and was tried first,
     but it reports nothing at all in an environment that is not compositing
     frames, which leaves every animated element stuck at its starting opacity.
     A rectangle can be measured whether or not anything is being drawn.
     ---------------------------------------------------------------------- */

  var watched = [];
  var ticking = false;

  function watch(element, run) {
    if (!element) {
      return;
    }

    if (reduced) {
      run();
      return;
    }

    watched.push({ element: element, run: run });
  }

  function inView(element, margin) {
    var rect = element.getBoundingClientRect();
    var height = window.innerHeight || root.clientHeight;

    return rect.top < height - (margin || 0) && rect.bottom > 0;
  }

  function sweep() {
    ticking = false;

    for (var i = watched.length - 1; i >= 0; i--) {
      if (inView(watched[i].element, 60)) {
        watched[i].run();
        watched.splice(i, 1);
      }
    }

    if (!watched.length) {
      window.removeEventListener('scroll', request);
      window.removeEventListener('resize', request);
    }
  }

  /* Throttled with a timer rather than requestAnimationFrame. A frame callback
     is never delivered to a page that is not being drawn, whether it is in a
     background tab or a panel nobody has opened, and an element that has still
     not been told to appear by the time somebody looks at it is a blank page.
     A timer fires either way. */
  function request() {
    if (ticking) {
      return;
    }

    ticking = true;
    window.setTimeout(sweep, 60);
  }

  window.addEventListener('scroll', request, { passive: true });
  window.addEventListener('resize', request, { passive: true });

  /* Reveals are only worth hiding once there is something here to unhide
     them. Until this class lands, .reveal has no effect at all. */
  root.classList.add('js-reveal');

  document.querySelectorAll('.reveal').forEach(function (el) {
    watch(el, function () {
      el.classList.add('is-visible');
    });
  });

  /* ---- The pipeline ----------------------------------------------------- */
  /* The six stages a scan really runs, in the order Scanner.ScanAsync runs
     them, lighting up one after another. */

  var pipeline = document.querySelector('.pipeline');

  watch(pipeline, function () {
    var stages = Array.prototype.slice.call(pipeline.children);

    if (reduced) {
      stages.forEach(function (s) { s.classList.add('is-done'); });
      return;
    }

    stages.forEach(function (stage, index) {
      window.setTimeout(function () {
        stage.classList.add('is-live');

        window.setTimeout(function () {
          stage.classList.remove('is-live');
          stage.classList.add('is-done');
        }, 520);
      }, index * 380);
    });
  });

  /* ---- Counting a score down -------------------------------------------- */
  /* From 100 to the real figure, because that is the direction the scoring
     model works in: a score is what is left once the worst finding has picked
     a band. */

  document.querySelectorAll('[data-count-to]').forEach(function (el) {
    var target = parseInt(el.getAttribute('data-count-to'), 10);
    var from = parseInt(el.getAttribute('data-count-from') || '100', 10);

    if (isNaN(target)) {
      return;
    }

    if (reduced) {
      el.textContent = target + '/100';
      return;
    }

    el.textContent = from + '/100';

    watch(el, function () {
      var started = null;
      var span = 1400;

      var step = function (now) {
        if (started === null) {
          started = now;
        }

        var progress = Math.min((now - started) / span, 1);
        var eased = 1 - Math.pow(1 - progress, 3);

        el.textContent = Math.round(from + (target - from) * eased) + '/100';

        if (progress < 1) {
          window.requestAnimationFrame(step);
        }
      };

      window.requestAnimationFrame(step);

      // The frame callbacks above do not arrive on a page that is not being
      // drawn, which would leave the reader looking at 100 out of 100 beside a
      // paragraph explaining why it is 11. This lands the real figure whether
      // the count ran or not.
      window.setTimeout(function () {
        el.textContent = target + '/100';
      }, span + 120);
    });
  });

  /* ---- Severity bars ---------------------------------------------------- */

  document.querySelectorAll('.ramp').forEach(function (ramp) {
    watch(ramp, function () {
      ramp.querySelectorAll('.ramp__fill').forEach(function (fill) {
        fill.style.width = fill.getAttribute('data-width') || '0%';
      });
    });
  });

  /* ---- Footer year ------------------------------------------------------ */

  var year = document.querySelector('[data-year]');

  if (year) {
    year.textContent = String(new Date().getFullYear());
  }

  /* First pass, for everything already on screen when the page opens. */
  sweep();

  /* A page opened at an anchor, or restored mid-scroll, settles after load. */
  window.addEventListener('load', request);
})();
