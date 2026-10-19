export function render(element: HTMLElement, detail: string): void {
  console.error(detail);
  element.textContent = detail;
  element.innerHTML = detail;
}
