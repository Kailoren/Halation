/* Highlights the table-of-contents entry for whichever section is currently in
   view. Driven by measurement on scroll rather than by an IntersectionObserver,
   for the same reason as the reveals in site.js. */

(function () {
  'use strict';

  var links = Array.prototype.slice.call(document.querySelectorAll('.toc a'));

  if (!links.length) {
    return;
  }

  var sections = links
    .map(function (link) {
      var id = link.getAttribute('href');
      return id && id.charAt(0) === '#'
        ? { link: link, target: document.getElementById(id.slice(1)) }
        : null;
    })
    .filter(function (pair) { return pair && pair.target; });

  var pending = false;

  function mark() {
    pending = false;

    // The section whose heading is highest on screen without having scrolled
    // past the top of the reading area. Falls back to the first, so something
    // is always marked rather than nothing being marked at the top of a page.
    var current = sections[0];

    sections.forEach(function (pair) {
      if (pair.target.getBoundingClientRect().top <= 120) {
        current = pair;
      }
    });

    sections.forEach(function (pair) {
      pair.link.classList.toggle('is-current', pair === current);
    });
  }

  function request() {
    if (pending) {
      return;
    }

    pending = true;
    window.setTimeout(mark, 90);
  }

  window.addEventListener('scroll', request, { passive: true });
  window.addEventListener('resize', request, { passive: true });
  mark();
})();
