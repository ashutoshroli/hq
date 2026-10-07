import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { settings } from "../api/client";
import { SettingsPage } from "../pages/SettingsPage";

describe("Settings page", () => {
  it("stores the analyst name and API key locally", async () => {
    render(
      <MemoryRouter>
        <SettingsPage />
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText("Analyst name"));
    await user.type(screen.getByLabelText("Analyst name"), "ravi");
    await user.type(screen.getByLabelText("API key"), "key-1");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(settings.getAnalyst()).toBe("ravi");
    expect(settings.getApiKey()).toBe("key-1");
    expect(screen.getByText("Saved.")).toBeInTheDocument();
  });
});
