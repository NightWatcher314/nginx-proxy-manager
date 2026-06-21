import { Field, useFormikContext } from "formik";
import { useState, type ClipboardEvent, type KeyboardEvent, type ReactNode } from "react";
import type { ActionMeta, MultiValue } from "react-select";
import CreatableSelect from "react-select/creatable";
import { intl, T } from "src/locale";
import { validateDomain, validateDomains } from "src/modules/Validations";

type SelectOption = {
	label: string;
	value: string;
	color?: string;
};

interface Props {
	id?: string;
	maxDomains?: number;
	isWildcardPermitted?: boolean;
	dnsProviderWildcardSupported?: boolean;
	name?: string;
	label?: string;
	onChange?: (domains: string[]) => void;
}
export function DomainNamesField({
	name = "domainNames",
	label = "domain-names",
	id = "domainNames",
	maxDomains,
	isWildcardPermitted = false,
	dnsProviderWildcardSupported = false,
	onChange,
}: Props) {
	const { setFieldValue } = useFormikContext();
	const [inputValue, setInputValue] = useState("");
	const allowWildcards = isWildcardPermitted && dnsProviderWildcardSupported;
	const isValidDomain = validateDomain(allowWildcards);

	const updateDomains = (doms: string[]) => {
		setFieldValue(name, doms);
		onChange?.(doms);
	};

	const handleChange = (v: MultiValue<SelectOption>, _actionMeta: ActionMeta<SelectOption>) => {
		const doms = v?.map((i: SelectOption) => {
			return i.value;
		});
		updateDomains(doms);
	};

	const addDomains = (currentDomains: string[], newDomains: string[]) => {
		const existing = new Set(currentDomains.map((d) => d.toLowerCase()));
		const doms = [...currentDomains];

		newDomains.forEach((rawDomain) => {
			const domain = rawDomain.trim();
			const duplicateKey = domain.toLowerCase();
			if (domain && isValidDomain(domain) && !existing.has(duplicateKey)) {
				doms.push(domain);
				existing.add(duplicateKey);
			}
		});

		if (doms.length !== currentDomains.length) {
			updateDomains(doms);
		}
	};

	const handleInputChange = (newValue: string) => {
		setInputValue(newValue);
		return newValue;
	};

	const helperTexts: ReactNode[] = [];
	if (maxDomains) {
		helperTexts.push(<T id="domain-names.max" data={{ count: maxDomains }} />);
	}
	if (!isWildcardPermitted) {
		helperTexts.push(<T id="domain-names.wildcards-not-permitted" />);
	} else if (!dnsProviderWildcardSupported) {
		helperTexts.push(<T id="domain-names.wildcards-not-supported" />);
	}

	return (
		<Field name={name} validate={validateDomains(allowWildcards, maxDomains)}>
			{({ field, form }: any) => {
				const handleKeyDown = (event: KeyboardEvent) => {
					if (event.key !== " " || !isValidDomain(inputValue)) {
						return;
					}

					event.preventDefault();
					addDomains(field.value ?? [], [inputValue]);
					setInputValue("");
				};

				const handlePaste = (event: ClipboardEvent) => {
					const pastedText = event.clipboardData.getData("text");
					const pastedDomains = pastedText.split(/[\s,]+/).filter(Boolean);

					if (!pastedDomains.length || pastedDomains.some((domain) => !isValidDomain(domain))) {
						return;
					}

					event.preventDefault();
					addDomains(field.value ?? [], pastedDomains);
					setInputValue("");
				};

				return (
					<div className="mb-3" onPaste={handlePaste}>
						<label className="form-label" htmlFor={id}>
							<T id={label} />
						</label>
						<CreatableSelect
							className="react-select-container"
							classNamePrefix="react-select"
							name={field.name}
							id={id}
							closeMenuOnSelect={true}
							isClearable={false}
							isValidNewOption={isValidDomain}
							isMulti
							placeholder={intl.formatMessage({ id: "domain-names.placeholder" })}
							inputValue={inputValue}
							onChange={handleChange}
							onInputChange={handleInputChange}
							onKeyDown={handleKeyDown}
							value={field.value?.map((d: string) => ({ label: d, value: d }))}
						/>
						{form.errors[field.name] && form.touched[field.name] ? (
							<small className="text-danger">{form.errors[field.name]}</small>
						) : helperTexts.length ? (
							helperTexts.map((i, idx) => (
								<small key={idx} className="text-info">
									{i}
								</small>
							))
						) : null}
					</div>
				);
			}}
		</Field>
	);
}
