export function render(element: HTMLElement, detail: string): void {
  console.warn(detail);
  element.textContent = detail;
  element.replaceChildren(document.createTextNode(detail));
}
