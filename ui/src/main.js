import { createApp } from "vue";
import "./lib/api.js";
import App from "./App.vue";
import router from "./router.js";
import "./styles/legacy.css";
import "./styles/base.css";

createApp(App).use(router).mount("#app");
