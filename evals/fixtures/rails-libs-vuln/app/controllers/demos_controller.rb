# Fixture: intentionally vulnerable Rails controller. FAKE data only.
# Covers CVE-2019-5418 (render file: arbitrary file read).
class DemosController < ApplicationController
  # SEC-01: request-derived path to render file: — arbitrary file read
  def show
    render file: params[:path]
  end

  # SAFE counterpart (must NOT trigger): first-party literal path
  def about
    render file: Rails.root.join("app/views/demos/about")
  end
end
