<?php

namespace Tests\Feature;

use App\Models\Client;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class ClientSearchControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_guest_cannot_search(): void
    {
        Client::factory()->create(['last_name' => 'Иванов']);

        $this->getJson('/clients/search?q=Иванов')->assertUnauthorized();
    }

    /**
     * @return array<string, array{bool}>
     */
    public static function everyRole(): array
    {
        return ['administrator' => [true], 'instructor' => [false]];
    }

    #[DataProvider('everyRole')]
    public function test_every_role_finds_clients_by_name_ordered_by_name(bool $isAdmin): void
    {
        Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Пётр', 'phone' => '+7 912 000-00-02']);
        Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Анна', 'middle_name' => 'Сергеевна', 'phone' => '+7 912 000-00-01']);
        Client::factory()->create(['last_name' => 'Петров', 'first_name' => 'Иван', 'phone' => '+7 912 000-00-03']);

        $this->actingAs($this->user($isAdmin))
            ->getJson('/clients/search?q=Иванов')
            ->assertOk()
            ->assertJsonCount(2, 'clients')
            ->assertJsonPath('clients.0.name', 'Иванов Анна Сергеевна')
            ->assertJsonPath('clients.0.phone', '+7 912 000-00-01')
            ->assertJsonPath('clients.1.name', 'Иванов Пётр');
    }

    public function test_every_word_of_the_term_has_to_match(): void
    {
        Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Пётр']);
        Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Анна']);

        $this->actingAs($this->user())
            ->getJson('/clients/search?q=Иванов Пётр')
            ->assertJsonCount(1, 'clients')
            ->assertJsonPath('clients.0.name', 'Иванов Пётр');
    }

    public function test_client_is_found_by_phone_however_it_was_typed(): void
    {
        $client = Client::factory()->create(['phone' => '+7 (912) 345-67-89']);
        Client::factory()->create(['phone' => '+7 912 000-00-00']);

        foreach (['9123456789', '345-67', '+7 (912) 345'] as $term) {
            $this->actingAs($this->user())
                ->getJson('/clients/search?q='.urlencode($term))
                ->assertJsonCount(1, 'clients')
                ->assertJsonPath('clients.0.id', $client->id);
        }
    }

    public function test_client_is_found_by_email(): void
    {
        $client = Client::factory()->create(['email' => 'anna@example.com']);
        Client::factory()->create(['email' => 'other@example.com']);

        $this->actingAs($this->user())
            ->getJson('/clients/search?q=anna@')
            ->assertJsonCount(1, 'clients')
            ->assertJsonPath('clients.0.id', $client->id);
    }

    public function test_blank_term_finds_nobody(): void
    {
        Client::factory()->count(3)->create();

        $this->actingAs($this->user())->getJson('/clients/search')->assertOk()->assertJsonPath('clients', []);
        $this->actingAs($this->user())->getJson('/clients/search?q=')->assertOk()->assertJsonPath('clients', []);
        $this->actingAs($this->user())->getJson('/clients/search?q=%20%20')->assertOk()->assertJsonPath('clients', []);
    }

    public function test_term_with_nothing_matching_finds_nobody(): void
    {
        Client::factory()->create(['last_name' => 'Иванов']);

        $this->actingAs($this->user())->getJson('/clients/search?q=Сидоров')->assertOk()->assertJsonPath('clients', []);
    }

    public function test_deleted_clients_are_not_offered(): void
    {
        Client::factory()->create(['last_name' => 'Иванов'])->delete();

        $this->actingAs($this->user())->getJson('/clients/search?q=Иванов')->assertOk()->assertJsonPath('clients', []);
    }

    public function test_only_ten_best_matches_are_returned(): void
    {
        foreach (range(1, 12) as $number) {
            Client::factory()->create(['last_name' => 'Тестов', 'first_name' => sprintf('Имя%02d', $number)]);
        }

        $this->actingAs($this->user())
            ->getJson('/clients/search?q=Тестов')
            ->assertJsonCount(10, 'clients')
            ->assertJsonPath('clients.0.name', 'Тестов Имя01')
            ->assertJsonPath('clients.9.name', 'Тестов Имя10');
    }

    public function test_term_that_is_too_long_is_rejected(): void
    {
        $this->actingAs($this->user())
            ->getJson('/clients/search?q='.str_repeat('а', 101))
            ->assertUnprocessable()
            ->assertJsonValidationErrors('q');
    }

    public function test_percent_and_underscore_in_the_term_are_ordinary_characters(): void
    {
        Client::factory()->create(['last_name' => 'Иванов']);

        $this->actingAs($this->user())->getJson('/clients/search?q=%25')->assertOk()->assertJsonPath('clients', []);
        $this->actingAs($this->user())->getJson('/clients/search?q=_')->assertOk()->assertJsonPath('clients', []);
    }

    public function test_result_exposes_only_what_the_search_box_shows(): void
    {
        Client::factory()->complete()->create(['last_name' => 'Иванов']);

        $this->actingAs($this->user())
            ->getJson('/clients/search?q=Иванов')
            ->assertJsonPath('clients.0', fn (array $client): bool => array_keys($client) === ['id', 'name', 'phone']);
    }

    private function user(bool $isAdmin = true): User
    {
        return $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
    }
}
