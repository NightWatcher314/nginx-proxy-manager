import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { Formik, useFormikContext } from "formik";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LocationsFields } from "./LocationsFields";

const { useAccessLists } = vi.hoisted(() => ({
	useAccessLists: vi.fn(() => ({ isLoading: false, isError: false, data: [{ id: 12, name: "Remote private" }] })),
}));
vi.mock("src/hooks", () => ({ useAccessLists }));
vi.mock("src/context", () => ({ useLocaleState: () => ({ locale: "en" }) }));
vi.mock("src/locale", () => ({
	T: ({ id }: { id: string }) => id,
	intl: { formatMessage: ({ id }: { id: string }) => id },
	formatDateTime: () => "fixture date",
}));
vi.mock("react-select", () => ({
	components: {},
	default: ({ value, options, onChange }: any) => (
		<select aria-label="location access list" value={value.value} onChange={(event) => onChange(options.find((option: any) => option.value === Number(event.target.value)))}>
			{options.map((option: any) => <option key={option.value} value={option.value}>{option.label}</option>)}
		</select>
	),
}));

function FormValues() {
	const { values } = useFormikContext();
	return <output data-testid="payload">{JSON.stringify(values)}</output>;
}

afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("location access lists on an Agent", () => {
	it("keeps the remaining row's ACL after deleting the first row and selects from the remote Agent", () => {
		const locations = ["/first", "/second"].map((path) => ({ path, forwardHost: "example.invalid", forwardPort: 80, forwardScheme: "http", advancedConfig: "", accessListId: 0 }));
		render(
			<Formik initialValues={{ locations }} onSubmit={() => {}}>
				<>
					<LocationsFields initialValues={locations} agentId="7" />
					<FormValues />
				</>
			</Formik>,
		);
		fireEvent.click(screen.getAllByRole("button", { name: "action.delete" })[0]);
		fireEvent.click(screen.getByRole("button", { name: /\/second/ }));
		fireEvent.change(screen.getByRole("combobox", { name: "location access list" }), { target: { value: "12" } });
		expect(useAccessLists).toHaveBeenCalledWith(["owner", "items", "clients"], {}, "7");
		const payload = JSON.parse(screen.getByTestId("payload").textContent || "{}");
		expect(payload.locations).toEqual([{ ...locations[1], accessListId: 12 }]);
		expect(screen.getByRole("combobox", { name: "location access list" })).toHaveValue("12");
	});
});
