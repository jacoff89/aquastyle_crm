<?php

namespace Tests\Feature;

use App\Models\Client;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class ClientControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_guest_is_redirected_to_login(): void
    {
        $client = Client::factory()->create();

        $this->get('/clients')->assertRedirect('/login');
        $this->get('/clients/create')->assertRedirect('/login');
        $this->post('/clients', $this->validPayload())->assertRedirect('/login');
        $this->get("/clients/{$client->id}")->assertRedirect('/login');
        $this->get("/clients/{$client->id}/edit")->assertRedirect('/login');
        $this->put("/clients/{$client->id}", $this->validPayload())->assertRedirect('/login');
        $this->delete("/clients/{$client->id}")->assertRedirect('/login');

        $this->assertDatabaseCount('clients', 1);
    }

    /**
     * @return array<string, array{bool}>
     */
    public static function everyRole(): array
    {
        return ['administrator' => [true], 'instructor' => [false]];
    }

    #[DataProvider('everyRole')]
    public function test_every_role_sees_the_whole_client_list_ordered_by_name(bool $isAdmin): void
    {
        Client::factory()->create(['last_name' => 'Петров', 'first_name' => 'Пётр', 'phone' => '+7 912 000-00-02']);
        Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Пётр', 'phone' => '+7 912 000-00-03']);
        Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Анна', 'middle_name' => 'Сергеевна', 'phone' => '+7 912 000-00-01', 'email' => 'anna@example.com']);

        $this->actingAs($this->user($isAdmin))
            ->get('/clients')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('clients/Index')
                ->has('clients.data', 3)
                ->where('clients.total', 3)
                ->where('clients.data.0.name', 'Иванов Анна Сергеевна')
                ->where('clients.data.0.phone', '+7 912 000-00-01')
                ->where('clients.data.0.email', 'anna@example.com')
                ->where('clients.data.1.name', 'Иванов Пётр')
                ->where('clients.data.2.name', 'Петров Пётр')
                ->where('filters', ['search' => '', 'sort' => 'name', 'direction' => 'asc']));
    }

    public function test_list_does_not_include_deleted_clients(): void
    {
        Client::factory()->create(['last_name' => 'Иванов']);
        Client::factory()->create(['last_name' => 'Удалённый'])->delete();

        $this->actingAs($this->user())
            ->get('/clients')
            ->assertInertia(fn (Assert $page) => $page
                ->has('clients.data', 1)
                ->where('clients.data.0.name', fn (string $name) => str_starts_with($name, 'Иванов')));
    }

    public function test_list_is_paginated_by_twenty_five(): void
    {
        Client::factory()->count(27)->create();

        $this->actingAs($this->user())
            ->get('/clients')
            ->assertInertia(fn (Assert $page) => $page
                ->has('clients.data', 25)
                ->where('clients.total', 27)
                ->where('clients.currentPage', 1)
                ->where('clients.lastPage', 2)
                ->where('clients.from', 1)
                ->where('clients.to', 25)
                ->where('clients.previousPageUrl', null)
                ->where('clients.nextPageUrl', fn (string $url) => str_ends_with($url, '/clients?page=2')));

        $this->actingAs($this->user())
            ->get('/clients?page=2')
            ->assertInertia(fn (Assert $page) => $page
                ->has('clients.data', 2)
                ->where('clients.from', 26)
                ->where('clients.to', 27)
                ->where('clients.nextPageUrl', null));
    }

    public function test_pagination_links_keep_search_and_sorting(): void
    {
        Client::factory()->count(26)->create(['last_name' => 'Иванов']);

        $this->actingAs($this->user())
            ->get('/clients?search=Иванов&sort=phone&direction=desc')
            ->assertInertia(fn (Assert $page) => $page
                ->where('clients.nextPageUrl', fn (string $url) => str_contains($url, 'search=') && str_contains($url, 'sort=phone') && str_contains($url, 'direction=desc')));
    }

    /**
     * SQLite compares only Latin letters without regard to case, so these
     * searches use the same case as the stored names; MySQL ignores case.
     *
     * @return array<string, array{string, list<string>}>
     */
    public static function searches(): array
    {
        return [
            'part of last name' => ['Иван', ['Иванов Анна']],
            'first name' => ['Пётр', ['Петров Пётр']],
            'middle name' => ['Сергеевна', ['Иванов Анна']],
            'last name and first name together' => ['Иванов Анна', ['Иванов Анна']],
            'words in any order' => ['Анна Иванов', ['Иванов Анна']],
            'email' => ['anna@', ['Иванов Анна']],
            'phone as typed' => ['+7 912 000-00-01', ['Иванов Анна']],
            'part of the phone' => ['000-00-02', ['Петров Пётр']],
            'digits only' => ['912000', ['Иванов Анна', 'Петров Пётр']],
            'no match' => ['Сидоров', []],
            'second word does not match' => ['Иванов Пётр', []],
            'percent sign is not a wildcard' => ['%', []],
            'underscore is not a wildcard' => ['Иван_в', []],
        ];
    }

    /**
     * @param  list<string>  $expected
     */
    #[DataProvider('searches')]
    public function test_search_finds_clients_by_name_phone_or_email(string $term, array $expected): void
    {
        Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Анна', 'middle_name' => 'Сергеевна', 'phone' => '+7 912 000-00-01', 'email' => 'anna@example.com']);
        Client::factory()->create(['last_name' => 'Петров', 'first_name' => 'Пётр', 'phone' => '8 (912) 000-00-02']);

        $this->actingAs($this->user())
            ->get('/clients?'.http_build_query(['search' => $term]))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->where('clients.total', count($expected))
                ->where('clients.data', fn ($rows) => collect($rows)->pluck('name')->every(
                    fn (string $name) => collect($expected)->contains(fn (string $wanted) => str_starts_with($name, $wanted)),
                ))
                ->where('filters.search', trim($term)));
    }

    public function test_phone_search_ignores_how_the_number_was_typed(): void
    {
        Client::factory()->create(['last_name' => 'Иванов', 'phone' => '8 (912) 345-67-89']);

        foreach (['+79123456789', '9123456789', '912 345', '345-67-89'] as $term) {
            $this->actingAs($this->user())
                ->get('/clients?'.http_build_query(['search' => $term]))
                ->assertInertia(fn (Assert $page) => $page->where('clients.total', 1));
        }
    }

    public function test_list_can_be_sorted_by_phone_and_by_date_added(): void
    {
        $first = Client::factory()->create(['last_name' => 'Яковлев', 'phone' => '+7 912 000-00-02']);
        $second = Client::factory()->create(['last_name' => 'Абрамов', 'phone' => '+7 912 000-00-01']);

        $this->actingAs($this->user())
            ->get('/clients?sort=phone')
            ->assertInertia(fn (Assert $page) => $page
                ->where('clients.data.0.id', $second->id)
                ->where('filters.sort', 'phone'));

        $this->actingAs($this->user())
            ->get('/clients?sort=phone&direction=desc')
            ->assertInertia(fn (Assert $page) => $page
                ->where('clients.data.0.id', $first->id)
                ->where('filters.direction', 'desc'));

        $this->actingAs($this->user())
            ->get('/clients?sort=created&direction=desc')
            ->assertInertia(fn (Assert $page) => $page->where('clients.data.0.id', $second->id));
    }

    public function test_unknown_sort_and_direction_fall_back_to_defaults(): void
    {
        Client::factory()->create();

        $this->actingAs($this->user())
            ->get('/clients?sort=password&direction=sideways')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page->where('filters.sort', 'name')->where('filters.direction', 'asc'));
    }

    public function test_list_does_not_expose_internal_columns(): void
    {
        Client::factory()->complete()->create();

        $this->actingAs($this->user())
            ->get('/clients')
            ->assertInertia(fn (Assert $page) => $page
                ->has('clients.data.0', fn (Assert $client) => $client
                    ->hasAll(['id', 'name', 'phone', 'email', 'createdAtLabel'])
                    ->missing('phone_digits')
                    ->missing('notes')));
    }

    public function test_create_form_has_no_client(): void
    {
        $this->actingAs($this->user())
            ->get('/clients/create')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page->component('clients/Form')->where('client', null));
    }

    #[DataProvider('everyRole')]
    public function test_every_role_adds_a_client(bool $isAdmin): void
    {
        $user = $this->user($isAdmin);

        $response = $this->actingAs($user)->post('/clients', $this->validPayload());

        $client = Client::where('last_name', 'Иванов')->sole();
        $response
            ->assertRedirect("/clients/{$client->id}")
            ->assertSessionHas('status', 'Добавлен клиент: Иванов Пётр Сергеевич.');

        $this->assertSame('Пётр', $client->first_name);
        $this->assertSame('Сергеевич', $client->middle_name);
        $this->assertSame('+7 912 345-67-89', $client->phone);
        $this->assertSame('79123456789', $client->phone_digits);
        $this->assertSame('petr@example.com', $client->email);
        $this->assertSame('1990-05-17', $client->birth_date->toDateString());
        $this->assertSame('Первый раз на воде', $client->notes);
        $this->assertTrue($client->creator->is($user));
    }

    public function test_only_last_name_first_name_and_phone_are_required(): void
    {
        $this->actingAs($this->user())
            ->post('/clients', ['last_name' => 'Иванов', 'first_name' => 'Пётр', 'phone' => '+7 912 345-67-89'])
            ->assertSessionHasNoErrors();

        $client = Client::sole();
        $this->assertNull($client->middle_name);
        $this->assertNull($client->email);
        $this->assertNull($client->birth_date);
        $this->assertNull($client->notes);
    }

    public function test_new_client_requires_last_name_first_name_and_phone(): void
    {
        $this->actingAs($this->user())
            ->post('/clients', [])
            ->assertSessionHasErrors([
                'last_name' => 'Поле «Фамилия» обязательно для заполнения.',
                'first_name' => 'Поле «Имя» обязательно для заполнения.',
                'phone' => 'Поле «Телефон» обязательно для заполнения.',
            ]);

        $this->assertDatabaseCount('clients', 0);
    }

    public function test_email_is_stored_in_lower_case(): void
    {
        $this->actingAs($this->user())
            ->post('/clients', $this->validPayload(['email' => '  Petr@Example.COM ']));

        $this->assertSame('petr@example.com', Client::sole()->email);
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalidInput(): array
    {
        return [
            'phone with letters' => [['phone' => '912-abc-45'], 'phone'],
            'phone too short' => [['phone' => '12-34'], 'phone'],
            'phone too long' => [['phone' => '+7 912 345 67 89 12 34 5'], 'phone'],
            'email without domain' => [['email' => 'petr@'], 'email'],
            'birth date in the future' => [['birth_date' => '2999-01-01'], 'birth_date'],
            'birth date before 1900' => [['birth_date' => '1899-12-31'], 'birth_date'],
            'birth date in another format' => [['birth_date' => '17.05.1990'], 'birth_date'],
            'last name too long' => [['last_name' => str_repeat('я', 101)], 'last_name'],
            'notes too long' => [['notes' => str_repeat('я', 2001)], 'notes'],
        ];
    }

    /**
     * @param  array<string, mixed>  $override
     */
    #[DataProvider('invalidInput')]
    public function test_invalid_input_is_rejected(array $override, string $field): void
    {
        $this->actingAs($this->user())
            ->post('/clients', $this->validPayload($override))
            ->assertSessionHasErrors($field);

        $this->assertDatabaseCount('clients', 0);
    }

    public function test_show_page_lists_client_details(): void
    {
        $client = Client::factory()->create([
            'last_name' => 'Иванов',
            'first_name' => 'Пётр',
            'middle_name' => 'Сергеевич',
            'phone' => '+7 912 345-67-89',
            'email' => 'petr@example.com',
            'birth_date' => '1990-05-17',
            'notes' => 'Первый раз на воде',
        ]);

        $this->actingAs($this->user())
            ->get("/clients/{$client->id}")
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('clients/Show')
                ->where('client.id', $client->id)
                ->where('client.fullName', 'Иванов Пётр Сергеевич')
                ->where('client.phone', '+7 912 345-67-89')
                ->where('client.email', 'petr@example.com')
                ->where('client.birthDate', '1990-05-17')
                ->where('client.birthDateLabel', '17.05.1990')
                ->where('client.notes', 'Первый раз на воде')
                ->missing('client.phone_digits'));
    }

    public function test_only_administrator_is_offered_deletion(): void
    {
        $client = Client::factory()->create();

        $this->actingAs($this->user(true))
            ->get("/clients/{$client->id}")
            ->assertInertia(fn (Assert $page) => $page->where('canDelete', true));

        $this->actingAs($this->user(false))
            ->get("/clients/{$client->id}")
            ->assertInertia(fn (Assert $page) => $page->where('canDelete', false));
    }

    public function test_deleted_client_is_not_found(): void
    {
        $client = Client::factory()->create();
        $client->delete();

        $admin = $this->user(true);

        $this->actingAs($admin)->get("/clients/{$client->id}")->assertNotFound();
        $this->actingAs($admin)->get("/clients/{$client->id}/edit")->assertNotFound();
        $this->actingAs($admin)->put("/clients/{$client->id}", $this->validPayload())->assertNotFound();
        $this->actingAs($admin)->delete("/clients/{$client->id}")->assertNotFound();
    }

    public function test_edit_form_shows_the_client(): void
    {
        $client = Client::factory()->create([
            'last_name' => 'Иванов',
            'first_name' => 'Пётр',
            'birth_date' => '1990-05-17',
        ]);

        $this->actingAs($this->user())
            ->get("/clients/{$client->id}/edit")
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('clients/Form')
                ->where('client.id', $client->id)
                ->where('client.lastName', 'Иванов')
                ->where('client.firstName', 'Пётр')
                ->where('client.birthDate', '1990-05-17')
                ->missing('client.phone_digits'));
    }

    #[DataProvider('everyRole')]
    public function test_every_role_updates_a_client(bool $isAdmin): void
    {
        $client = Client::factory()->create(['phone' => '+7 900 000-00-00']);

        $this->actingAs($this->user($isAdmin))
            ->put("/clients/{$client->id}", $this->validPayload())
            ->assertRedirect("/clients/{$client->id}")
            ->assertSessionHas('status', 'Изменения сохранены: Иванов Пётр Сергеевич.');

        $client->refresh();
        $this->assertSame('Иванов', $client->last_name);
        $this->assertSame('+7 912 345-67-89', $client->phone);
        $this->assertSame('79123456789', $client->phone_digits);
        $this->assertSame('petr@example.com', $client->email);
    }

    public function test_update_does_not_change_who_added_the_client(): void
    {
        $author = $this->user(true);
        $client = Client::factory()->create(['created_by' => $author->id]);

        $this->actingAs($this->user(false))->put("/clients/{$client->id}", $this->validPayload(['created_by' => 999]));

        $this->assertSame($author->id, $client->fresh()->created_by);
    }

    public function test_update_clears_optional_fields_left_empty(): void
    {
        $client = Client::factory()->complete()->create();

        $this->actingAs($this->user())
            ->put("/clients/{$client->id}", $this->validPayload(['middle_name' => '', 'email' => '', 'birth_date' => '', 'notes' => '']))
            ->assertSessionHasNoErrors();

        $client->refresh();
        $this->assertNull($client->middle_name);
        $this->assertNull($client->email);
        $this->assertNull($client->birth_date);
        $this->assertNull($client->notes);
    }

    public function test_invalid_update_changes_nothing(): void
    {
        $client = Client::factory()->create(['last_name' => 'Иванов']);

        $this->actingAs($this->user())
            ->put("/clients/{$client->id}", $this->validPayload(['last_name' => '']))
            ->assertSessionHasErrors(['last_name' => 'Поле «Фамилия» обязательно для заполнения.']);

        $this->assertSame('Иванов', $client->fresh()->last_name);
    }

    public function test_administrator_deletes_a_client_without_losing_the_record(): void
    {
        $client = Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Пётр']);

        $this->actingAs($this->user(true))
            ->delete("/clients/{$client->id}")
            ->assertRedirect('/clients')
            ->assertSessionHas('status', 'Клиент удалён: Иванов Пётр. История занятий сохранится.');

        $this->assertSoftDeleted('clients', ['id' => $client->id]);
    }

    public function test_instructor_can_not_delete_a_client(): void
    {
        $client = Client::factory()->create();

        $this->actingAs($this->user(false))->delete("/clients/{$client->id}")->assertForbidden();

        $this->assertNotSoftDeleted('clients', ['id' => $client->id]);
    }

    private function user(bool $isAdmin = true): User
    {
        return $isAdmin ? User::factory()->admin()->create() : User::factory()->create();
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
            'middle_name' => 'Сергеевич',
            'phone' => '+7 912 345-67-89',
            'email' => 'petr@example.com',
            'birth_date' => '1990-05-17',
            'notes' => 'Первый раз на воде',
            ...$overrides,
        ];
    }
}
