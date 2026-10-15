import { createContext, Fragment, useContext, useLayoutEffect, useState } from 'react';

import { PinRawContext, StatusBanner } from '@/components/Primitives';
import { mergeEdits } from '@/mergeEdits';

// Rendered by a form that cannot represent its value: the drawer switches to
// raw mode, with the form disabled and `supports` explaining why.
export function UnsupportedInForm(props: { supports: string }) {
	const pin = useContext(PinRawContext);
	useLayoutEffect(() => {
		pin?.(`The form editor only supports ${props.supports}, so this is edited as raw YAML.`);
	}, [pin, props.supports]);
	return null;
}

// Receives an editor's current value, so a drawer can read it without
// submitting the form (and so without the editor's save validation).
export const EditorValueContext = createContext<((value: unknown) => void) | null>(null);

export function useReportEditorValue(value: unknown) {
	useContext(EditorValueContext)?.(value);
}

// Structured editors save through this: `edited` is the value rebuilt from form
// state, and the first one seen is the editor's baseline. Returns the edit
// applied onto `original` (see mergeEdits) and any paths it would replace.
// Pass `edited` before any cleanup that drops modeled fields (e.g. implied
// defaults) and apply that cleanup to the result. `reset` makes a value loaded
// into the form (e.g. from raw mode) the new original.
export function useMergedEdits<T>(original: unknown, edited: T) {
	const [base, setBase] = useState<{ original: unknown; baseline: { value: T } | null }>(() => ({
		original,
		baseline: { value: edited }
	}));
	useLayoutEffect(() => {
		if (!base.baseline) setBase({ original: base.original, baseline: { value: edited } });
	});
	const reset = (value: unknown) => setBase({ original: value, baseline: null });
	const baseline = base.baseline ? base.baseline.value : edited;
	const merged =
		base.original === null || base.original === undefined
			? { value: edited, lost: [] as string[] }
			: mergeEdits(base.original, baseline, edited);
	useReportEditorValue(merged.value);
	return { value: merged.value as T, lost: merged.lost, reset };
}

export function LostFieldsWarning(props: { lost: string[] }) {
	if (!props.lost.length) return null;
	const paths = props.lost.filter(path => path !== '.');
	return (
		<StatusBanner state="warn" title="This form cannot show all of this configuration">
			Saving will overwrite{' '}
			{paths.length === props.lost.length
				? paths.map((path, index) => (
						<Fragment key={path}>
							{index ? ', ' : null}
							<code>{path}</code>
						</Fragment>
					))
				: 'parts of it'}
			. Edit it as raw YAML (the code icon) to keep them.
		</StatusBanner>
	);
}
