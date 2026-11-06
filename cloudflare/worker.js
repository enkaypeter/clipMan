import { Container } from "@cloudflare/containers";

export class ClipmanContainer extends Container {
  defaultPort = 8080;
  sleepAfter = "5m";
  enableInternet = true;
  envVars = Object.fromEntries([
    "MONGO_URI", "MONGO_DB", "JWT_SECRET", "APP_PORT", "GIN_MODE",
    "WORKOS_API_KEY", "WORKOS_CLIENT_ID", "SESSION_COOKIE_NAME",
    "SESSION_COOKIE_SECURE", "SESSION_COOKIE_SAME_SITE",
    "SESSION_DURATION", "CORS_ALLOW_ORIGINS"
  ].filter(key => typeof this.env[key] === "string")
   .map(key => [key, this.env[key]]));
}

export default {
  fetch(request, env) {
    return env.CLIPMAN.getByName("clipman-production").fetch(request);
  }
};
