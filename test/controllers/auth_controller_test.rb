require "test_helper"

class AuthControllerTest < ActionDispatch::IntegrationTest
  test "customer signup creates a user and returns a token" do
    assert_difference("User.count", 1) do
      post signup_customer_url,
        params: {
          user: {
            name: "Rider One",
            email: "RIDER@example.com",
            phone: "9999999999",
            password: "password123",
            password_confirmation: "password123",
            role: "driver"
          }
        },
        as: :json
    end

    assert_response :created

    body = JSON.parse(response.body)
    assert body["token"].present?
    assert_equal "rider@example.com", body.dig("user", "email")
    assert_equal "user", body.dig("user", "role")
    assert_nil body.dig("user", "password_digest")
  end

  test "driver signup creates a driver and returns a token" do
    assert_difference("User.count", 1) do
      post signup_driver_url,
        params: {
          user: {
            name: "Driver One",
            email: "DRIVER@example.com",
            phone: "8888888888",
            password: "password123",
            password_confirmation: "password123",
            role: "user"
          }
        },
        as: :json
    end

    assert_response :created

    body = JSON.parse(response.body)
    assert body["token"].present?
    assert_equal "driver@example.com", body.dig("user", "email")
    assert_equal "driver", body.dig("user", "role")
    assert_nil body.dig("user", "password_digest")
  end

  test "customer signup rejects invalid user data" do
    assert_no_difference("User.count") do
      post signup_customer_url,
        params: { user: { email: "", password: "password123" } },
        as: :json
    end

    assert_response :unprocessable_entity
    assert JSON.parse(response.body)["errors"].present?
  end

  test "login returns a token for valid credentials" do
    user = User.create!(
      name: "Driver One",
      email: "driver@example.com",
      phone: "8888888888",
      password: "password123",
      role: :driver
    )

    post login_url,
      params: { email: user.email, password: "password123" },
      as: :json

    assert_response :ok

    body = JSON.parse(response.body)
    assert body["token"].present?
    assert_equal user.id, JwtService.decode(body["token"])["user_id"]
    assert_equal "driver", body.dig("user", "role")
  end

  test "login rejects invalid credentials" do
    User.create!(
      name: "Wrong Password",
      email: "wrong-password@example.com",
      phone: "7777777777",
      password: "password123",
      role: :user
    )

    post login_url,
      params: { email: "wrong-password@example.com", password: "bad-password" },
      as: :json

    assert_response :unauthorized
    assert_equal "Invalid email or password", JSON.parse(response.body)["error"]
  end
end
