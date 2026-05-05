/**
 * Keyboard input-mode toggle for the mobile text-input bar.
 *
 * Two modes:
 *
 *   - **assisted** — `autocorrect=on`, `autocapitalize=sentences`,
 *     `spellcheck=true`. The phone OS helps you type — word
 *     completion, autocorrect, smart capitalization. Right for
 *     prose-y input (chat, comments, commit messages typed into a
 *     remote shell).
 *
 *   - **raw** — `autocorrect=off`, `autocapitalize=off`,
 *     `spellcheck=false`, `autocomplete=off`. The OS stays out of
 *     the way. Right for shell commands, code, file paths — places
 *     where "the" autocorrected to "they" is the wrong move.
 *
 * Persisted via localStorage so the user's pick survives reload.
 * Default is assisted (the historical behavior).
 */

const STORAGE_KEY = "pty-relay:keyboard-mode";

export type KeyboardMode = "assisted" | "raw";
const VALID: ReadonlyArray<KeyboardMode> = ["assisted", "raw"];
const DEFAULT_MODE: KeyboardMode = "assisted";

export function loadKeyboardMode(): KeyboardMode {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw && (VALID as ReadonlyArray<string>).includes(raw)) {
      return raw as KeyboardMode;
    }
  } catch {}
  return DEFAULT_MODE;
}

export function saveKeyboardMode(mode: KeyboardMode): void {
  try {
    localStorage.setItem(STORAGE_KEY, mode);
  } catch {
    // private mode / quota — best effort.
  }
}

/** Apply a mode to the supplied textarea. The browser does NOT
 *  re-evaluate these attributes mid-edit, so any text already typed
 *  in stays as-is. The change takes effect on the next focus +
 *  keystroke. iOS in particular needs the textarea to lose focus
 *  and refocus before the new attribute set takes hold; we don't
 *  force that here, since blurring while the user is mid-edit
 *  would be more annoying than the delayed apply. */
export function applyKeyboardMode(
  textarea: HTMLTextAreaElement,
  mode: KeyboardMode
): void {
  if (mode === "raw") {
    textarea.setAttribute("autocorrect", "off");
    textarea.setAttribute("autocapitalize", "off");
    textarea.setAttribute("autocomplete", "off");
    textarea.setAttribute("spellcheck", "false");
  } else {
    textarea.setAttribute("autocorrect", "on");
    textarea.setAttribute("autocapitalize", "sentences");
    textarea.setAttribute("autocomplete", "on");
    textarea.setAttribute("spellcheck", "true");
  }
}

export interface KeyboardModeController {
  current(): KeyboardMode;
  set(mode: KeyboardMode): void;
  toggle(): void;
}

/** Wire a textarea to a persistent mode toggle. The optional
 *  `onChange` callback fires whenever the mode changes (so the
 *  toolbar button can update its label / aria-pressed). */
export function createKeyboardModeController(
  textarea: HTMLTextAreaElement,
  onChange?: (mode: KeyboardMode) => void
): KeyboardModeController {
  let mode: KeyboardMode = loadKeyboardMode();
  applyKeyboardMode(textarea, mode);
  // Notify caller so the UI starts in sync.
  if (onChange) onChange(mode);

  function set(next: KeyboardMode): void {
    if (next === mode) return;
    mode = next;
    applyKeyboardMode(textarea, mode);
    saveKeyboardMode(mode);
    if (onChange) onChange(mode);
  }

  return {
    current: () => mode,
    set,
    toggle: () => set(mode === "assisted" ? "raw" : "assisted"),
  };
}
