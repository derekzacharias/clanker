import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

// jsdom lacks these APIs; provide deterministic stubs so components behave.
beforeEach(() => {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }),
  });
  window.scrollTo = vi.fn();
  // Radix popper (tooltips, popovers) measures its anchor with ResizeObserver, which jsdom does
  // not implement. A no-op stub is honest here: layout is verified in a real browser by the
  // Playwright checks, not in jsdom.
  if (!("ResizeObserver" in globalThis)) {
    Object.defineProperty(globalThis, "ResizeObserver", {
      writable: true,
      value: class {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    });
  }
  Object.assign(navigator, {
    clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
  localStorage.clear();
  document.documentElement.className = "";
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
