import { reactive } from "vue";

export const ui = reactive({
  liveCount: 0,
  settingsOpen: false,
  reportOpen: false,
});

export function openSettings() {
  ui.settingsOpen = true;
}

export function closeSettings() {
  ui.settingsOpen = false;
}
