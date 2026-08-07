/* ============================================================================
   The rule reference

   rules.json is generated from RuleEngine.DefaultRules rather than written by
   hand, so this page cannot drift away from the checks the scanner actually
   runs. Regenerate it whenever the catalogue changes; see docs/README.md.
   ========================================================================= */

(function () {
  'use strict';

  var listEl = document.getElementById('rules');
  var familiesEl = document.getElementById('families');
  var filtersEl = document.getElementById('family-filters');
  var searchEl = document.getElementById('rule-search');
  var countEl = document.getElementById('rule-count');

  if (!listEl) {
    return;
  }

  var rules = [];
  var active = 'all';
  var query = '';

  /* Escaped on the way in, because everything here is interpolated into markup
     and a rule description is text from a file rather than a literal here. */
  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function severityChip(severity) {
    return '<span class="chip chip--' + esc(String(severity).toLowerCase()) + '">'
      + esc(severity) + '</span>';
  }

  function renderFamilies(families) {
    familiesEl.innerHTML = families.map(function (family) {
      // Deliberately not a .reveal. These cards are created after site.js has
      // taken its inventory of what to animate, so one marked for reveal would
      // never be told to appear and would sit at opacity zero for good.
      return '<div class="card">'
        + '<span class="feature__icon">VC-' + esc(family.prefix) + '-###</span>'
        + '<h3>' + esc(family.name) + '</h3>'
        + '<p style="color:var(--muted);font-size:0.95rem;margin:0">' + esc(family.description) + '</p>'
        + '</div>';
    }).join('');
  }

  function renderFilters(families, present) {
    var buttons = ['<button class="pill" type="button" data-family="all" aria-pressed="true">All</button>'];

    families.forEach(function (family) {
      if (present.indexOf(family.prefix) === -1) {
        return;
      }

      buttons.push('<button class="pill" type="button" data-family="' + esc(family.prefix)
        + '" aria-pressed="false">' + esc(family.name) + '</button>');
    });

    filtersEl.innerHTML = buttons.join('');

    filtersEl.addEventListener('click', function (event) {
      var button = event.target.closest('button[data-family]');

      if (!button) {
        return;
      }

      active = button.getAttribute('data-family');

      Array.prototype.forEach.call(filtersEl.querySelectorAll('button'), function (other) {
        other.setAttribute('aria-pressed', String(other === button));
      });

      render();
    });
  }

  function matches(rule) {
    if (active !== 'all' && rule.family !== active) {
      return false;
    }

    if (!query) {
      return true;
    }

    var haystack = [rule.id, rule.title, rule.description, rule.userDescription, rule.remediation]
      .join(' ')
      .toLowerCase();

    return haystack.indexOf(query) !== -1;
  }

  function renderRule(rule) {
    var flags = [];

    if (rule.blocking) {
      flags.push('<span class="flag flag--block">can advise against installing</span>');
    }

    if (rule.capability) {
      flags.push('<span class="flag flag--cap">a capability, not a defect</span>');
    }

    if (rule.languages && rule.languages.length) {
      flags.push('<span class="flag">' + esc(rule.languages.join(', ')) + ' only</span>');
    }

    var sameForBoth = rule.severity === rule.userSeverity
      && rule.description === rule.userDescription;

    return '<article class="rule" data-severity="' + esc(rule.severity) + '">'
      + '<div class="rule__head">'
      + '<span class="rule__id">' + esc(rule.id) + '</span>'
      + '<h3 class="rule__title">' + esc(rule.title) + '</h3>'
      + '</div>'
      + '<div class="rule__body">'
      + (sameForBoth
        ? '<p>' + esc(rule.description) + '</p>'
          + '<div class="rule__reader"><div><h4>Rated ' + severityChip(rule.severity)
            + ' for both readers</h4><p style="margin:0">The same finding either way. '
            + 'Reachability depends on how the application uses it, and guessing downwards '
            + 'would tell somebody a real flaw is not their problem.</p></div></div>'
        : '<div class="rule__reader">'
          + '<div><h4>Shipping it ' + severityChip(rule.severity) + '</h4>'
          + '<p style="margin:0">' + esc(rule.description) + '</p></div>'
          + '<div><h4>Running it ' + severityChip(rule.userSeverity) + '</h4>'
          + '<p style="margin:0">' + esc(rule.userDescription) + '</p></div>'
          + '</div>')
      + '<p style="margin-top:0.9rem"><strong style="color:var(--text)">Fix:</strong> '
        + esc(rule.remediation) + '</p>'
      + (flags.length ? '<div class="rule__flags">' + flags.join('') + '</div>' : '')
      + '</div>'
      + '</article>';
  }

  function render() {
    var shown = rules.filter(matches);

    listEl.innerHTML = shown.length
      ? shown.map(renderRule).join('')
      : '<p class="empty">No rule matches that. Try a shorter word, or clear the filter.</p>';

    countEl.textContent = shown.length === rules.length
      ? rules.length + ' checks'
      : shown.length + ' of ' + rules.length;
  }

  if (searchEl) {
    searchEl.addEventListener('input', function () {
      query = searchEl.value.trim().toLowerCase();
      render();
    });
  }

  fetch('assets/js/rules.json')
    .then(function (response) {
      if (!response.ok) {
        throw new Error('HTTP ' + response.status);
      }

      return response.json();
    })
    .then(function (data) {
      rules = data.rules || [];

      var present = rules.map(function (rule) { return rule.family; });

      renderFamilies(data.families || []);
      renderFilters(data.families || [], present);
      render();
    })
    .catch(function (error) {
      listEl.innerHTML = '<p class="empty">The rule catalogue could not be loaded ('
        + esc(error.message) + '). It is in '
        + '<a href="https://github.com/kailoren/halation/tree/main/Halation.Core/Rules">'
        + 'Halation.Core/Rules</a> in the source.</p>';

      if (familiesEl) {
        familiesEl.innerHTML = '';
      }
    });
})();
