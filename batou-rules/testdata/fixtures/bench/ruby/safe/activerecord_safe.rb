require 'sinatra'
require 'active_record'
require 'json'

# SAFE: ActiveRecord parameterized where clause
get '/users/search' do
  query = params[:q]
  users = User.where('username ILIKE ?', "%#{query}%").limit(50)
  content_type :json
  users.to_json(only: [:id, :username, :email])
end

# SAFE: ActiveRecord find_by (automatically parameterized)
get '/users/:id' do
  user = User.find_by(id: params[:id])
  halt 404, { error: 'Not found' }.to_json unless user
  content_type :json
  user.to_json(only: [:id, :username, :email])
end

# SAFE: ActiveRecord create (mass assignment with strong params pattern)
post '/users' do
  allowed = %i[username email]
  attrs = JSON.parse(request.body.read).slice(*allowed.map(&:to_s))
  user = User.create!(attrs)
  status 201
  content_type :json
  { id: user.id }.to_json
end

# SAFE: ActiveRecord update with parameterized conditions
put '/users/:id/bio' do
  bio = JSON.parse(request.body.read)['bio']
  User.where(id: params[:id]).update_all(['bio = ?', bio])
  { success: true }.to_json
end

# SAFE: Arel query builder (parameterized)
get '/products' do
  term = params[:q]
  products = Product.where(Product.arel_table[:name].matches("%#{term}%"))
                    .order(:name)
                    .limit(20)
  content_type :json
  products.to_json
end
