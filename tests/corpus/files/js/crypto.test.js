const { createHash } = require("crypto");

test("vector", () => {
  expect(createHash('sha384').update("").digest("hex")).toBeTruthy();
});
