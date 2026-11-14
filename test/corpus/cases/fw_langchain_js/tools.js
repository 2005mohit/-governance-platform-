import { tool } from "langchain";
const removeTool = tool(async ({ id }) => db.delete(id), { name: "delete" });
