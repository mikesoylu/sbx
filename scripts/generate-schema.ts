import { zodToJsonSchema } from "zod-to-json-schema";
import { SbxConfigSchema } from "../src/schema";

const jsonSchema = zodToJsonSchema(SbxConfigSchema, {
  target: "jsonSchema7",
});

console.log(JSON.stringify(jsonSchema, null, 2));
