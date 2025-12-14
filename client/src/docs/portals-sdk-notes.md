# Portals Iframe SDK Notes

These notes describe how HUD overlays (iframes) are expected to talk to the Portals Unity environment.

## Global PortalsSdk object

The Portals SDK script (for example:

`https://portals-labs.github.io/portals-sdk/portals-sdk.js`

) exposes a global `PortalsSdk` object with at least:

- `PortalsSdk.PortalsWindow` – usually the iframe window (same as `window`)
- `PortalsSdk.PortalsParent` – usually the parent Portals/Unity container (same as `window.parent`)
- `PortalsSdk.Origin` – map of known environment base URLs, for example:
  - `PortalsSdk.Origin.Localhost`
  - `PortalsSdk.Origin.Dev`
  - `PortalsSdk.Origin.Prev`
  - `PortalsSdk.Origin.Prod`

You can use these origins when checking `event.origin` in `postMessage` handlers.

## Basic message pattern

The iframe HUD should:

1. **Listen for messages** from the parent (Unity/Portals):

```js
window.addEventListener('message', (event) => {
  // (Optional) check that the origin matches one of the expected origins:
  // if (event.origin !== PortalsSdk.Origin.Localhost) return;

  const data = event.data;
  if (!data || typeof data !== 'object') return;

  switch (data.type) {
    case 'HUD_INIT':
      // parent is telling us initial state
      break;
    case 'HUD_UPDATE':
      // parent is sending updated HUD props (health, score, etc.)
      break;
    default:
      break;
  }
});
```
2. **Send messages back to the parent**:

```js
function sendToPortals(message) {
  const target = PortalsSdk?.PortalsParent || window.parent;
  // You can choose a targetOrigin based on the environment
  const targetOrigin = PortalsSdk?.Origin?.Dev || '*';

  target.postMessage(message, targetOrigin);
}

// Example: notify Unity that the HUD is ready
sendToPortals({ type: 'HUD_READY', payload: { version: '1.0.0' } });
```


# Important constraints for GPT

- All HUD code lives in the iframe (HTML/CSS/JS only).
- The backend is NOT part of the Portals SDK; do not invent new HTTP endpoints.
- Prefer examples that:
    - Use PortalsSdk.PortalsParent and window.postMessage.
    - Include basic event.origin checks where appropriate.
    - Keep state in the iframe or Unity, not on a random server.