class AuthController < ApplicationController
  skip_forgery_protection only: %i[signup_customer signup_driver login]

  def signup_customer
    signup_with_role(:user)
  end

  def signup_driver
    signup_with_role(:driver)
  end

  def login
    credentials = login_params
    user = User.find_by(email: credentials[:email].to_s.strip.downcase)

    if user&.authenticate(credentials[:password])
      render json: auth_payload(user), status: :ok
    else
      render json: { error: "Invalid email or password" }, status: :unauthorized
    end
  end

  private

  def signup_with_role(role)
    user = User.new(signup_params)
    user.role = role

    if user.save
      render json: auth_payload(user), status: :created
    else
      render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
    end
  end

  def auth_payload(user)
    {
      token: JwtService.encode(user_id: user.id),
      user: user.as_json(only: %i[id name email phone role])
    }
  end

  def signup_params
    permitted = auth_params.permit(:name, :email, :phone, :password, :password_confirmation)
    permitted[:email] = permitted[:email].to_s.strip.downcase if permitted[:email].present?
    permitted
  end

  def login_params
    auth_params.permit(:email, :password)
  end

  def auth_params
    params[:user].present? ? params.require(:user) : params
  end
end
