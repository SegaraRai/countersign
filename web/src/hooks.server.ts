import { handle as stillwindHandle } from "@stillwind/integration/sveltekit/handle";
import { sequence } from "@sveltejs/kit/hooks";

export const handle = sequence(stillwindHandle);
