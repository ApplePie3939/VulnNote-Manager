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
