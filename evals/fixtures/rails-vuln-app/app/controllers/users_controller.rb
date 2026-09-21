# Fixture: intentionally insecure controller.
class UsersController < ApplicationController
  # SEC-03: CSRF verification skipped for every action here
  skip_before_action :verify_authenticity_token
  # SEC-04: no authenticate/authorize before_action anywhere

  def index
    # SEC-01: SQL injection via string interpolation
    @users = User.where("name = '#{params[:name]}'")
  end

  def create
    # SEC-05: mass assignment — permit! opens every column (admin included)
    user = User.new(user_params)
    user.save
    render json: user
  end

  def show
    @user = User.find(params[:id])
  end

  def export
    # SEC-06: path traversal via user-controlled path
    send_file(params[:path])
  end

  def switch
    # SEC-07: arbitrary method dispatch
    self.public_send(params[:method])
  end

  private

  def user_params
    params.require(:user).permit!   # SEC-05
  end
end
