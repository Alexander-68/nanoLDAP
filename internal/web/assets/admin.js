(() => {
  const openDialog = (dialogId) => {
    if (!dialogId) {
      return;
    }
    const dialog = document.getElementById(dialogId);
    if (dialog instanceof HTMLDialogElement && !dialog.open) {
      dialog.showModal();
    }
  };

  document.addEventListener("click", (event) => {
    const closeButton = event.target.closest("[data-close-dialog]");
    if (closeButton) {
      closeButton.closest("dialog")?.close();
      return;
    }

    const trigger = event.target.closest("[data-dialog-id]");
    if (!trigger) {
      return;
    }
    openDialog(trigger.getAttribute("data-dialog-id"));
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") {
      return;
    }
    const trigger = event.target.closest("[data-dialog-id]");
    if (!trigger) {
      return;
    }
    event.preventDefault();
    openDialog(trigger.getAttribute("data-dialog-id"));
  });
})();
