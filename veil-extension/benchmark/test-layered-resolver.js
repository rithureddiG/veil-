/**
 * Unit Test: Layered Evidence-Based Action Resolver
 */

const assert = require('assert');
const { JSDOM } = require('jsdom');
const resolver = require('../core/action-resolver');

console.log('Testing Layered Evidence-Based Action Resolver...');

const html = `
<!DOCTYPE html>
<html>
<body>
  <form id="checkout-form">
    <div class="field">
      <label for="card-input">Credit Card Number</label>
      <input id="card-input" name="card_number" type="text" placeholder="16-digit card number" />
    </div>
    <div class="actions">
      <button id="submit-order-btn" type="submit" aria-label="Confirm and Place Order Now">Place Order</button>
      <button id="cancel-btn" type="button">Cancel</button>
    </div>
  </form>
</body>
</html>
`;

const dom = new JSDOM(html);
const doc = dom.window.document;

// 1. Direct ID match
let res = resolver.resolveTargetWithEvidence({ id: 'submit-order-btn' }, doc);
assert.strictEqual(res.element.id, 'submit-order-btn');
assert.strictEqual(res.confidence, 'HIGH');
assert.strictEqual(res.score, 1.0);
console.log('  ✔ Direct ID match resolved with 100% confidence.');

// 2. Semantic Natural Language Match with Multi-Signal Agreement
res = resolver.resolveTargetWithEvidence({ description: 'Place Order', role: 'button' }, doc);
assert.strictEqual(res.element.id, 'submit-order-btn');
assert(res.score >= 0.40);
console.log(`  ✔ Button resolved with evidence score: ${res.score} (Confidence: ${res.confidence})`);

// 3. Accessible Name Match ("Confirm and Place Order Now")
res = resolver.resolveTargetWithEvidence({ description: 'Confirm and Place Order', role: 'button' }, doc);
assert.strictEqual(res.element.id, 'submit-order-btn');
console.log(`  ✔ Accessible ARIA name match resolved successfully (Score: ${res.score})`);

// 4. Form Field Resolution ("Credit Card Number")
res = resolver.resolveTargetWithEvidence({ description: 'Credit Card Number' }, doc);
assert.strictEqual(res.element.id, 'card-input');
console.log(`  ✔ Form input resolved via label and name associations (Score: ${res.score})`);

// 5. Total Non-Match Rejection (Unresolvable / Low Confidence -> fails closed to null)
res = resolver.resolveTargetWithEvidence({ description: 'Completely Unrelated Button 12345' }, doc);
assert.strictEqual(res.element, null);
assert.strictEqual(res.confidence, 'LOW');
console.log('  ✔ Unresolvable target strictly rejected (failed closed to null).');

// 6. Backwards compatibility test
const compatEl = resolver.resolveTarget({ description: 'Place Order' }, doc);
assert.strictEqual(compatEl.id, 'submit-order-btn');
console.log('  ✔ Backwards-compatible resolveTarget() returned expected element.');

console.log('✅ ALL LAYERED RESOLVER TESTS PASSED\n');
