<?php

namespace GeneaLabs\LaravelSignInWithApple\Providers;

use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;

class SignInWithAppleProvider extends AbstractProvider implements ProviderInterface
{
    public static $runsMigrations = true;

    protected $encodingType = PHP_QUERY_RFC3986;
    protected $scopeSeparator = " ";

    public static function ignoreMigrations()
    {
        static::$runsMigrations = false;
    }

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            'https://appleid.apple.com/auth/authorize',
            $state
        );
    }

    protected function getCodeFields($state = null)
    {
        $fields = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'response_type' => 'code',
            'response_mode' => 'form_post',
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        return array_merge($fields, $this->parameters);
    }

    protected function getTokenUrl()
    {
        return "https://appleid.apple.com/auth/token";
    }

    public function getAccessToken($code)
    {
        $response = $this->getHttpClient()
            ->post(
                $this->getTokenUrl(),
                [
                    'headers' => ['Authorization' => 'Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret)],
                    'body'    => $this->getTokenFields($code),
                ]
            );

        return $this->parseAccessToken($response->getBody());
    }

    protected function parseAccessToken($response)
    {
        $data = $response->json();

        return $data['access_token'];
    }

    protected function getTokenFields($code)
    {
        $fields = parent::getTokenFields($code);
        $fields["grant_type"] = "authorization_code";

        return $fields;
    }

    protected function getUserByToken($token)
    {
        $claims = explode('.', $token)[1];

        return json_decode(base64_decode($claims), true);
    }

    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $user = $this->mapUserToObject($this->getUserByToken(
            Arr::get($response, 'id_token')
        ));

        return $user
            ->setToken(Arr::get($response, 'access_token'))
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

    public function login()
    {
        $statelessUser = $this->user();
        $userClass = config("auth.providers.users.model");
        $user = (new $userClass)
            ->firstOrNew([
                "siwa_sub" => $statelessUser->user["sub"],
            ]);

        $user->siwa_sub = $statelessUser->user["sub"];
        $user->password = Str::random(64);
        $user->name = $statelessUser->name;
        $user->email = $statelessUser->email;
        $user->save();

        auth()->login($user);
    
        return $user;
    }

    protected function mapUserToObject(array $user)
    {
        if (request()->filled("user")) {
            $user["name"] = json_decode(request("user"), true)["name"];
            $fullName = trim(
                ($user["name"]['firstName'] ?? "")
                . " "
                . ($user["name"]['lastName']) ?? ""
            );
        }

        return (new User)
            ->setRaw($user)
            ->map([
                'name' => $fullName ?? null,
                'email' => $user['email'] ?? null,
            ]);
    }
}
