<?php

namespace Tests\Feature;

use App\Models\Client;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class ClientChildTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_child_can_be_created_without_a_phone(): void
    {
        $parent = Client::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->post('/clients', ['last_name' => 'Иванов', 'first_name' => 'Петя', 'parent_id' => $parent->id])
            ->assertSessionHasNoErrors();

        $child = Client::query()->where('first_name', 'Петя')->firstOrFail();
        $this->assertTrue($child->parent->is($parent));
        $this->assertNull($child->phone);
        $this->assertNull($child->phone_digits);
    }

    public function test_phone_is_required_without_a_parent(): void
    {
        $this->actingAs(User::factory()->admin()->create())
            ->post('/clients', ['last_name' => 'Иванов', 'first_name' => 'Петя'])
            ->assertSessionHasErrors('phone');
    }

    public function test_child_cannot_have_children(): void
    {
        $child = Client::factory()->create(['parent_id' => Client::factory()->create()->id]);

        $this->actingAs(User::factory()->admin()->create())
            ->post('/clients', ['last_name' => 'Иванов', 'first_name' => 'Петя', 'parent_id' => $child->id])
            ->assertSessionHasErrors('parent_id');
    }

    public function test_client_with_children_cannot_become_a_child(): void
    {
        $parent = Client::factory()->create();
        Client::factory()->create(['parent_id' => $parent->id]);
        $other = Client::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->put("/clients/{$parent->id}", ['last_name' => 'А', 'first_name' => 'Б', 'phone' => $parent->phone, 'parent_id' => $other->id])
            ->assertSessionHasErrors('parent_id');
    }

    public function test_list_shows_children_under_their_parent(): void
    {
        $parent = Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Анна']);
        Client::factory()->create(['last_name' => 'Яблоков', 'first_name' => 'Ян', 'parent_id' => $parent->id, 'phone' => null]);
        Client::factory()->create(['last_name' => 'Петров', 'first_name' => 'Пётр']);

        $this->actingAs(User::factory()->admin()->create())
            ->get('/clients')
            ->assertInertia(fn (Assert $page) => $page
                ->where('clients.total', 2)
                ->where('clients.data.0.name', 'Иванов Анна')
                ->where('clients.data.0.isChild', false)
                ->where('clients.data.1.name', 'Яблоков Ян')
                ->where('clients.data.1.isChild', true)
                ->where('clients.data.2.name', 'Петров Пётр'));
    }

    public function test_search_lists_matching_children_with_the_parent_name(): void
    {
        $parent = Client::factory()->create(['last_name' => 'Иванов', 'first_name' => 'Анна']);
        Client::factory()->create(['last_name' => 'Яблоков', 'first_name' => 'Ян', 'parent_id' => $parent->id, 'phone' => null]);

        $this->actingAs(User::factory()->admin()->create())
            ->get('/clients?search=Яблоков')
            ->assertInertia(fn (Assert $page) => $page
                ->has('clients.data', 1)
                ->where('clients.data.0.isChild', true)
                ->where('clients.data.0.parentName', 'Иванов Анна'));
    }
}
