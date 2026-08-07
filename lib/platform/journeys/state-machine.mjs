export function transition(machine, state, event) {
  const transitionRule = machine?.transitions?.find((item) => item.from === state && item.event === event);
  return transitionRule ? { status: 'pass', from: state, event, to: transitionRule.to } : { status: 'blocked', from: state, event, reason: 'unsealed-transition' };
}
