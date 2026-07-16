"use strict";

document.querySelectorAll("[data-timezone-offset]").forEach((input) => {
  input.value = String(new Date().getTimezoneOffset());
});

document.querySelectorAll("time[data-local-time]").forEach((element) => {
  const parsed = new Date(element.dateTime);
  if (!Number.isNaN(parsed.valueOf())) {
    element.textContent = parsed.toLocaleString();
  }
});

document.querySelectorAll("input[data-utc-input]").forEach((input) => {
  const parsed = new Date(input.dataset.utcInput);
  if (!Number.isNaN(parsed.valueOf())) {
    const local = new Date(parsed.valueOf() - parsed.getTimezoneOffset() * 60000);
    input.value = local.toISOString().slice(0, 16);
  }
});

document.querySelectorAll("form[method='post']").forEach((form) => {
  form.addEventListener("submit", () => {
    const button = form.querySelector("button[type='submit']");
    if (button) {
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      button.textContent = "処理中…";
    }
  });
});

const projectFilter = document.querySelector("#note-project");
const targetFilter = document.querySelector("[data-target-filter]");
if (projectFilter && targetFilter) {
  const updateTargetOptions = () => {
    const projectId = projectFilter.value;
    targetFilter.querySelectorAll("option[data-project-id]").forEach((option) => {
      const available = !projectId || option.dataset.projectId === projectId;
      option.hidden = !available;
      option.disabled = !available;
      if (!available && option.selected) {
        targetFilter.value = "";
      }
    });
  };
  projectFilter.addEventListener("change", updateTargetOptions);
  updateTargetOptions();
}
