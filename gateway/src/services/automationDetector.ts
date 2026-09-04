/**
 * Automation / WebDriver artifact detector.
 *
 * navigator.webdriver === true is the standard W3C WebDriver flag — set by
 * Selenium, Playwright, and Puppeteer (in non-stealth configurations) on
 * every real navigator object. It is the single strongest client-side
 * automation signal available: no genuine human browser ever sets it.
 *
 * The other properties below are legacy injection artifacts left behind by
 * specific automation tools even when navigator.webdriver itself is patched
 * out by a "stealth" plugin — checking several independently raises the bar
 * for evasion rather than relying on one flag alone.
 */

export interface AutomationFingerprint {
  webdriver?: boolean;             // navigator.webdriver
  hasChromedriverCdc?: boolean;    // window/document $cdc_ properties (older ChromeDriver)
  hasPhantomArtifact?: boolean;    // window.callPhantom / window._phantom
  hasNightmareArtifact?: boolean;  // window.__nightmare (Nightmare.js)
  pluginsLength?: number;          // navigator.plugins.length (real Chrome: >0)
  languagesEmpty?: boolean;        // navigator.languages.length === 0
}

export interface AutomationVerdict {
  detected: boolean;
  reasons: string[];
}

/** Collects reasons independently so a caller can log *why*, not just a bit. */
export function detectAutomation(fp: AutomationFingerprint): AutomationVerdict {
  const reasons: string[] = [];

  if (fp.webdriver === true) reasons.push('navigator.webdriver=true');
  if (fp.hasChromedriverCdc) reasons.push('chromedriver $cdc_ artifact');
  if (fp.hasPhantomArtifact) reasons.push('phantomjs artifact');
  if (fp.hasNightmareArtifact) reasons.push('nightmare.js artifact');
  // Only treat as a signal when combined with an empty language list, since
  // pluginsLength alone also legitimately hits 0 on some hardened/mobile
  // browsers — this pairing is a much rarer, more specific combination.
  if (fp.pluginsLength === 0 && fp.languagesEmpty) {
    reasons.push('headless combo: 0 plugins + empty languages');
  }

  return { detected: reasons.length > 0, reasons };
}
