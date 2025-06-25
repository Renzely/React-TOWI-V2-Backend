const mongoose = require("mongoose");

const expiryEntrySchema = new mongoose.Schema(
  {
    month: String,
    quantity: Number,
  },
  { _id: false }
);

const skuSchema = new mongoose.Schema(
  {
    sku: String,
    skuCode: String,
    beginningPCS: Number,
    deliveryPCS: Number,
    endingPCS: Number,
    offtake: Number,
    inventoryDays: Number,
    expiry: [expiryEntrySchema],
  },
  { _id: false }
);

const simpleSkuSchema = new mongoose.Schema(
  {
    sku: String,
    skuCode: String,
  },
  { _id: false }
);

const versionSchema = new mongoose.Schema(
  {
    Carried: [skuSchema],
    "Not Carried": [simpleSkuSchema],
    Delisted: [simpleSkuSchema],
  },
  { _id: false }
);

const groupedInventorySchema = new mongoose.Schema({
  email: String,
  date: String,
  merchandiser: String,
  outlet: String,
  weeksCovered: String,
  month: String,
  week: String,
  locked: {
    type: Boolean,
    default: false,
  },
  versions: {
    V1: versionSchema,
    V2: versionSchema,
    V3: versionSchema,
  },
});

const Inventory = mongoose.model("inventoryProcess", groupedInventorySchema);
module.exports = Inventory;
