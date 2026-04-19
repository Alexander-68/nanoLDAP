(() => {
  const collator = new Intl.Collator(undefined, { sensitivity: "base", numeric: true });

  const openDialog = (dialogId) => {
    if (!dialogId) return;
    const dialog = document.getElementById(dialogId);
    if (dialog instanceof HTMLDialogElement && !dialog.open) {
      dialog.showModal();
    }
  };

  const isTypingTarget = (el) => {
    if (!el) return false;
    if (el.isContentEditable) return true;
    const tag = el.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
  };

  const anyDialogOpen = () =>
    Array.from(document.querySelectorAll("dialog")).some((d) => d.open);

  const getRows = () =>
    Array.from(document.querySelectorAll(".interactive-row[data-dialog-id]"))
      .filter((r) => !r.hidden);

  const focusRow = (row) => {
    if (!row) return;
    row.focus();
    row.scrollIntoView({ block: "nearest", inline: "nearest" });
  };

  const currentRowIndex = (rows) => rows.indexOf(document.activeElement);

  // --- Sorting --------------------------------------------------------- //

  const sortTable = (table, key, direction) => {
    const tbody = table.tBodies[0];
    if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll("tr.interactive-row"));
    if (!rows.length) return;
    const dir = direction === "descending" ? -1 : 1;
    rows.sort((a, b) => {
      const av = (a.querySelector(`[data-col="${key}"]`)?.textContent || "").trim();
      const bv = (b.querySelector(`[data-col="${key}"]`)?.textContent || "").trim();
      return collator.compare(av, bv) * dir;
    });
    const fragment = document.createDocumentFragment();
    rows.forEach((r) => fragment.appendChild(r));
    tbody.appendChild(fragment);
    table.querySelectorAll("th[data-sort-key]").forEach((th) => {
      th.setAttribute("aria-sort", th.dataset.sortKey === key ? direction : "none");
    });
  };

  const toggleSort = (th) => {
    const table = th.closest("table");
    if (!table) return;
    const current = th.getAttribute("aria-sort");
    const next = current === "ascending" ? "descending" : "ascending";
    sortTable(table, th.dataset.sortKey, next);
  };

  // --- Search ---------------------------------------------------------- //

  const applySearch = (input) => {
    const scope = input.closest("[data-search-scope]");
    if (!scope) return;
    const q = input.value.trim().toLowerCase();
    const rows = scope.querySelectorAll("tbody tr[data-search]");
    let visible = 0;
    rows.forEach((row) => {
      const hay = (row.dataset.search || "").toLowerCase();
      const match = !q || hay.includes(q);
      row.hidden = !match;
      if (match) visible++;
    });
    const empty = scope.querySelector("[data-search-empty]");
    if (empty) empty.hidden = !(q && rows.length > 0 && visible === 0);
  };

  // --- Click / tap delegation ----------------------------------------- //

  document.addEventListener("click", (event) => {
    const closeButton = event.target.closest("[data-close-dialog]");
    if (closeButton) {
      closeButton.closest("dialog")?.close();
      return;
    }
    const sortHeader = event.target.closest("th[data-sort-key]");
    if (sortHeader) {
      toggleSort(sortHeader);
      return;
    }
    const trigger = event.target.closest("[data-dialog-id]");
    if (!trigger) return;
    openDialog(trigger.getAttribute("data-dialog-id"));
  });

  // --- Input delegation (search) -------------------------------------- //

  document.addEventListener("input", (event) => {
    if (event.target.matches("[data-search-input]")) applySearch(event.target);
  });

  // --- Keydown -------------------------------------------------------- //

  document.addEventListener("keydown", (event) => {
    // Search-input-local keys: ArrowDown jumps into rows, Escape clears.
    if (event.target.matches?.("[data-search-input]")) {
      if (event.key === "ArrowDown") {
        const rows = getRows();
        if (rows.length) {
          event.preventDefault();
          focusRow(rows[0]);
        }
        return;
      }
      if (event.key === "Escape" && event.target.value) {
        event.preventDefault();
        event.target.value = "";
        applySearch(event.target);
        return;
      }
      return; // let the input handle the rest natively
    }

    // Enter / Space on a focused sort header or dialog trigger.
    if (event.key === "Enter" || event.key === " ") {
      const sortHeader = event.target.closest("th[data-sort-key]");
      if (sortHeader) {
        event.preventDefault();
        toggleSort(sortHeader);
        return;
      }
      const trigger = event.target.closest("[data-dialog-id]");
      if (trigger) {
        event.preventDefault();
        openDialog(trigger.getAttribute("data-dialog-id"));
        return;
      }
    }

    // Global shortcuts: skip if typing or a modal is open.
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if (isTypingTarget(event.target)) return;
    if (anyDialogOpen()) return;

    const rows = getRows();
    switch (event.key) {
      case "ArrowDown":
        if (!rows.length) return;
        event.preventDefault();
        focusRow(rows[Math.min(rows.length - 1, currentRowIndex(rows) + 1)] || rows[0]);
        return;
      case "ArrowUp": {
        if (!rows.length) return;
        event.preventDefault();
        const idx = currentRowIndex(rows);
        focusRow(idx > 0 ? rows[idx - 1] : rows[0]);
        return;
      }
      case "Home":
        if (!rows.length) return;
        event.preventDefault();
        focusRow(rows[0]);
        return;
      case "End":
        if (!rows.length) return;
        event.preventDefault();
        focusRow(rows[rows.length - 1]);
        return;
      case "+":
      case "=":
      case "n":
      case "N": {
        const btn = document.querySelector(".page-header [data-dialog-id$='-create-modal']");
        if (!btn) return;
        event.preventDefault();
        openDialog(btn.getAttribute("data-dialog-id"));
        return;
      }
      case "/": {
        const searchInput = document.querySelector("[data-search-input]");
        if (!searchInput) return;
        event.preventDefault();
        searchInput.focus();
        searchInput.select();
        return;
      }
      case "1":
        event.preventDefault();
        window.location.assign("/users");
        return;
      case "2":
        event.preventDefault();
        window.location.assign("/groups");
        return;
      case "g":
      case "G":
        if (!document.getElementById("base-dn-modal")) return;
        event.preventDefault();
        openDialog("base-dn-modal");
        return;
      case "?":
        if (!document.getElementById("keyboard-help-modal")) return;
        event.preventDefault();
        openDialog("keyboard-help-modal");
        return;
    }
  });
})();
