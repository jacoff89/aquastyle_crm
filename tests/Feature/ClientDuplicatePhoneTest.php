<?php

namespace Tests\Feature;

use App\Models\Client;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class ClientDuplicatePhoneTest extends TestCase
{
    use LazilyRefreshDatabase;

    private const DUPLICATE_MESSAGE = 'Клиент с таким телефоном уже есть. Проверьте, что это не дубль.';

    public function test_guest_can_not_look_up_duplicates(): void
    {
        $this->getJson('/clients/duplicates?phone=%2B79123456789')->assertUnauthorized();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function sameNumberTypedDifferently(): array
    {
        return [
            'international with spaces' => ['+7 912 345-67-89'],
            'international without separators' => ['+79123456789'],
            'with eight' => ['8 (912) 345-67-89'],
            'without country code' => ['912 345 67 89'],
        ];
    }

    #[DataProvider('sameNumberTypedDifferently')]
    public function test_lookup_finds_the_same_number_however_it_is_typed(string $phone): void
    {
        $existing = Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Пётр', 'phone' => '8 912 345 67 89']);
        Client::factory()->create(['phone' => '+7 999 000-00-00']);

        $this->actingAs(User::factory()->create())
            ->getJson('/clients/duplicates?'.http_build_query(['phone' => $phone]))
            ->assertOk()
            ->assertExactJson(['duplicates' => [
                ['id' => $existing->id, 'name' => 'Иванов Пётр', 'phone' => '8 912 345 67 89'],
            ]]);
    }

    public function test_lookup_returns_nothing_for_a_new_number(): void
    {
        Client::factory()->create(['phone' => '+7 912 345-67-89']);

        $this->actingAs(User::factory()->create())
            ->getJson('/clients/duplicates?phone=%2B79990000000')
            ->assertOk()
            ->assertExactJson(['duplicates' => []]);
    }

    public function test_lookup_skips_the_client_being_edited_and_deleted_clients(): void
    {
        $edited = Client::factory()->create(['phone' => '+7 912 345-67-89']);
        Client::factory()->create(['phone' => '+7 912 345-67-89'])->delete();

        $this->actingAs(User::factory()->create())
            ->getJson('/clients/duplicates?'.http_build_query(['phone' => '+7 912 345-67-89', 'except' => $edited->id]))
            ->assertOk()
            ->assertExactJson(['duplicates' => []]);
    }

    public function test_lookup_shows_at_most_five_clients(): void
    {
        Client::factory()->count(6)->create(['phone' => '+7 912 345-67-89']);

        $this->actingAs(User::factory()->create())
            ->getJson('/clients/duplicates?phone=%2B79123456789')
            ->assertJsonCount(5, 'duplicates');
    }

    public function test_lookup_requires_a_phone(): void
    {
        $this->actingAs(User::factory()->create())
            ->getJson('/clients/duplicates')
            ->assertUnprocessable()
            ->assertJsonValidationErrors('phone');
    }

    #[DataProvider('sameNumberTypedDifferently')]
    public function test_adding_a_client_with_an_existing_phone_needs_confirmation(string $phone): void
    {
        Client::factory()->create(['phone' => '8 912 345 67 89']);

        $this->actingAs(User::factory()->create())
            ->post('/clients', $this->validPayload(['phone' => $phone]))
            ->assertSessionHasErrors(['phone' => self::DUPLICATE_MESSAGE]);

        $this->assertDatabaseCount('clients', 1);
    }

    public function test_confirmed_duplicate_is_saved(): void
    {
        Client::factory()->create(['phone' => '+7 912 345-67-89']);

        $this->actingAs(User::factory()->create())
            ->post('/clients', $this->validPayload(['confirm_duplicate' => true]))
            ->assertSessionHasNoErrors();

        $this->assertDatabaseCount('clients', 2);
    }

    public function test_confirmation_flag_is_not_stored_on_the_client(): void
    {
        $this->actingAs(User::factory()->create())
            ->post('/clients', $this->validPayload(['confirm_duplicate' => true]))
            ->assertSessionHasNoErrors();

        $this->assertArrayNotHasKey('confirm_duplicate', Client::sole()->getAttributes());
    }

    public function test_phone_of_a_deleted_client_is_not_a_duplicate(): void
    {
        Client::factory()->create(['phone' => '+7 912 345-67-89'])->delete();

        $this->actingAs(User::factory()->create())
            ->post('/clients', $this->validPayload())
            ->assertSessionHasNoErrors();
    }

    public function test_client_can_keep_own_phone_when_edited(): void
    {
        $client = Client::factory()->create(['phone' => '8 912 345 67 89']);

        $this->actingAs(User::factory()->create())
            ->put("/clients/{$client->id}", $this->validPayload(['phone' => '+7 912 345-67-89']))
            ->assertSessionHasNoErrors();

        $this->assertSame('+7 912 345-67-89', $client->fresh()->phone);
    }

    public function test_editing_to_the_phone_of_another_client_needs_confirmation(): void
    {
        Client::factory()->create(['phone' => '+7 912 345-67-89']);
        $client = Client::factory()->create(['phone' => '+7 900 000-00-00']);
        $user = User::factory()->create();

        $this->actingAs($user)
            ->put("/clients/{$client->id}", $this->validPayload())
            ->assertSessionHasErrors(['phone' => self::DUPLICATE_MESSAGE]);

        $this->assertSame('+7 900 000-00-00', $client->fresh()->phone);

        $this->actingAs($user)
            ->put("/clients/{$client->id}", $this->validPayload(['confirm_duplicate' => true]))
            ->assertSessionHasNoErrors();

        $this->assertSame('+7 912 345-67-89', $client->fresh()->phone);
    }

    public function test_phone_digits_follow_the_phone_when_it_changes(): void
    {
        $client = Client::factory()->create(['phone' => '+7 900 000-00-00']);
        $this->assertSame('79000000000', $client->phone_digits);

        $client->update(['phone' => '8 (912) 345-67-89']);

        $this->assertSame('79123456789', $client->fresh()->phone_digits);
    }

    public function test_phone_must_have_between_seven_and_fifteen_digits(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->post('/clients', $this->validPayload(['phone' => '+1 23 45']))
            ->assertSessionHasErrors(['phone' => 'Телефон должен содержать от 7 до 15 цифр.']);

        $this->actingAs($user)
            ->post('/clients', $this->validPayload(['phone' => '+1 234 5678']))
            ->assertSessionHasNoErrors();
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private function validPayload(array $overrides = []): array
    {
        return [
            'last_name' => 'Иванов',
            'first_name' => 'Пётр',
            'phone' => '+7 912 345-67-89',
            ...$overrides,
        ];
    }
}
