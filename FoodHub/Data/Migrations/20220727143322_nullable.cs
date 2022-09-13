using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FoodHub.Data.Migrations
{
    public partial class nullable : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Items_Discounts_DiscountId",
                table: "Items");

            migrationBuilder.DropForeignKey(
                name: "FK_Items_Recipes_RecipeId",
                table: "Items");

            migrationBuilder.DropIndex(
                name: "IX_Items_DiscountId",
                table: "Items");

            migrationBuilder.DropIndex(
                name: "IX_Items_RecipeId",
                table: "Items");

            migrationBuilder.AlterColumn<Guid>(
                name: "RecipeId",
                table: "Items",
                type: "uniqueidentifier",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uniqueidentifier");

            migrationBuilder.AlterColumn<Guid>(
                name: "DiscountId",
                table: "Items",
                type: "uniqueidentifier",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uniqueidentifier");

            migrationBuilder.CreateIndex(
                name: "IX_Items_DiscountId",
                table: "Items",
                column: "DiscountId",
                unique: true,
                filter: "[DiscountId] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_Items_RecipeId",
                table: "Items",
                column: "RecipeId",
                unique: true,
                filter: "[RecipeId] IS NOT NULL");

            migrationBuilder.AddForeignKey(
                name: "FK_Items_Discounts_DiscountId",
                table: "Items",
                column: "DiscountId",
                principalTable: "Discounts",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_Items_Recipes_RecipeId",
                table: "Items",
                column: "RecipeId",
                principalTable: "Recipes",
                principalColumn: "Id");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Items_Discounts_DiscountId",
                table: "Items");

            migrationBuilder.DropForeignKey(
                name: "FK_Items_Recipes_RecipeId",
                table: "Items");

            migrationBuilder.DropIndex(
                name: "IX_Items_DiscountId",
                table: "Items");

            migrationBuilder.DropIndex(
                name: "IX_Items_RecipeId",
                table: "Items");

            migrationBuilder.AlterColumn<Guid>(
                name: "RecipeId",
                table: "Items",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                oldClrType: typeof(Guid),
                oldType: "uniqueidentifier",
                oldNullable: true);

            migrationBuilder.AlterColumn<Guid>(
                name: "DiscountId",
                table: "Items",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                oldClrType: typeof(Guid),
                oldType: "uniqueidentifier",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Items_DiscountId",
                table: "Items",
                column: "DiscountId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Items_RecipeId",
                table: "Items",
                column: "RecipeId",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_Items_Discounts_DiscountId",
                table: "Items",
                column: "DiscountId",
                principalTable: "Discounts",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Items_Recipes_RecipeId",
                table: "Items",
                column: "RecipeId",
                principalTable: "Recipes",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
